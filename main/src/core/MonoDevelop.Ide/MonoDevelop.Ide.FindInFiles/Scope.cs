﻿//
// Scope.cs
//
// Author:
//       Mike Krüger <mkrueger@novell.com>
//
// Copyright (c) 2009 Novell, Inc (http://www.novell.com)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using System.Linq;
using System.IO;
using System.Collections.Generic;
using MonoDevelop.Projects;
using MonoDevelop.Ide.Gui;
using MonoDevelop.Core;
using System.Security.Permissions;
using System.Security;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Text;
using Microsoft.VisualStudio.Text.Editor;
using System.Threading;

namespace MonoDevelop.Ide.FindInFiles
{
	abstract class Scope
	{
		[Obsolete ("Unused - will be removed")]
		public bool IncludeBinaryFiles {
			get;
			set;
		}

		public virtual PathMode PathMode {
			get {
				var workspace = IdeApp.Workspace;
				var solutions = workspace != null ? workspace.GetAllSolutions () : null;

				if (solutions != null && solutions.Count () == 1)
					return PathMode.Relative;

				return PathMode.Absolute;
			}
		}

		public abstract int GetTotalWork (FilterOptions filterOptions);

		protected static readonly Task<IReadOnlyList<FileProvider>> EmptyFileProviderTask = Task.FromResult<IReadOnlyList<FileProvider>> (new FileProvider [0]);

		public abstract Task<IReadOnlyList<FileProvider>> GetFilesAsync (FilterOptions filterOptions, CancellationToken cancellationToken = default);

		[Obsolete ("Use GetFilesAsync")]
		public virtual IEnumerable<FileProvider> GetFiles (ProgressMonitor monitor, FilterOptions filterOptions)
		{
			throw new NotImplementedException ();
		}

		public abstract string GetDescription (FilterOptions filterOptions, string pattern, string replacePattern);

		public virtual bool ValidateSearchOptions (FilterOptions filterOptions) => true;
	}

	class DocumentScope : Scope
	{
		public override PathMode PathMode {
			get { return PathMode.Hidden; }
		}

		public override int GetTotalWork (FilterOptions filterOptions)
		{
			return 1;
		}

		public override Task<IReadOnlyList<FileProvider>> GetFilesAsync (FilterOptions filterOptions, CancellationToken cancellationToken = default)
		{
			var doc = IdeApp.Workbench.ActiveDocument;
			var textBuffer = doc.GetContent<ITextBuffer> ();
			if (textBuffer != null)
				return Task.FromResult<IReadOnlyList<FileProvider>> (new [] { new OpenFileProvider (textBuffer, doc.Owner as Project, doc.FileName) });
			return EmptyFileProviderTask;
		}

		public override string GetDescription(FilterOptions filterOptions, string pattern, string replacePattern)
		{
			if (replacePattern == null)
				return GettextCatalog.GetString("Looking for '{0}' in current document", pattern);
			return GettextCatalog.GetString("Replacing '{0}' in current document", pattern);
		}

	}

	class SelectionScope : Scope
	{
		public override PathMode PathMode {
			get { return PathMode.Hidden; }
		}

		public override int GetTotalWork (FilterOptions filterOptions)
		{
			return 1;
		}

		public override Task<IReadOnlyList<FileProvider>> GetFilesAsync (FilterOptions filterOptions, CancellationToken cancellationToken = default)
		{
			var doc = IdeApp.Workbench.ActiveDocument;
			var textView = doc.GetContent<ITextView> (true);
			if (textView != null) {
				var selection = textView.Selection.SelectedSpans.FirstOrDefault ();
				return Task.FromResult<IReadOnlyList<FileProvider>> (new [] { new OpenFileProvider (textView.TextBuffer, doc.Owner as Project, doc.FileName, selection.Start, selection.End) });
			}
			return EmptyFileProviderTask;
		}

		public override string GetDescription(FilterOptions filterOptions, string pattern, string replacePattern)
		{
			if (replacePattern == null)
				return GettextCatalog.GetString("Looking for '{0}' in current selection", pattern);
			return GettextCatalog.GetString("Replacing '{0}' in current selection", pattern);
		}

	}

	class WholeSolutionScope : Scope
	{
		public override int GetTotalWork (FilterOptions filterOptions)
		{
			int result = 0;
			if (IdeApp.Workspace.IsOpen)
				result = IdeApp.Workspace.GetAllProjects ().Sum (p => p.Files.Count);
			return result;
		}

		public override Task<IReadOnlyList<FileProvider>> GetFilesAsync (FilterOptions filterOptions, CancellationToken cancellationToken = default)
		{
			if (!IdeApp.Workspace.IsOpen) {
				return EmptyFileProviderTask;
			}

			var alreadyVisited = new HashSet<string> ();
			var results = new List<FileProvider> ();

			var options = new ParallelOptions ();
			options.MaxDegreeOfParallelism = 4;

			Parallel.ForEach (IdeApp.Workspace.GetAllSolutionItems ().OfType<SolutionFolder> (),
							  options,
							  () => new List<FileProvider> (),
							  (folder, loop, providers) => {
								  foreach (var file in folder.Files.Where (f => filterOptions.NameMatches (f.FileName) && File.Exists (f.FullPath))) {
									  if (!IdeServices.DesktopService.GetFileIsText (file.FullPath))
										  continue;
									  lock (alreadyVisited) {
										  if (alreadyVisited.Contains (file.FullPath))
											  continue;
										  alreadyVisited.Add (file.FullPath);
									  }
									  providers.Add (new FileProvider (file.FullPath));
								  }
								  return providers;
							  },
							  (providers) => {
								  lock (results) {
									  results.AddRange (providers);
								  }
							  });

			Parallel.ForEach (IdeApp.Workspace.GetAllProjects (),
							  options,
							  () => new List<FileProvider> (),
							  (project, loop, providers) => {
								  var conf = project.DefaultConfiguration?.Selector;

								  foreach (ProjectFile file in project.GetSourceFilesAsync (conf).Result) {
									  if ((file.Flags & ProjectItemFlags.Hidden) == ProjectItemFlags.Hidden)
										  continue;
									  if (!filterOptions.IncludeCodeBehind && file.Subtype == Subtype.Designer)
										  continue;
									  if (!filterOptions.NameMatches (file.Name))
										  continue;
									  if (!IdeServices.DesktopService.GetFileIsText (file.FilePath))
										  continue;

									  lock (alreadyVisited) {
										  if (alreadyVisited.Contains (file.FilePath.FullPath))
											  continue;
										  alreadyVisited.Add (file.FilePath.FullPath);
									  }

									  providers.Add (new FileProvider (file.Name, project));
								  }
								  return providers;
							  },
							  (providers) => {
								  lock (results) {
									  results.AddRange (providers);
								  }
							  });

			return EmptyFileProviderTask;
		}

		public override string GetDescription (FilterOptions filterOptions, string pattern, string replacePattern)
		{
			if (replacePattern == null)
				return GettextCatalog.GetString ("Looking for '{0}' in all projects", pattern);
			return GettextCatalog.GetString ("Replacing '{0}' in all projects", pattern);
		}
	}

	class WholeProjectScope : Scope
	{
		readonly Project project;

		public override int GetTotalWork (FilterOptions filterOptions)
		{
			return project.Files.Count;
		}

		public WholeProjectScope (Project project)
		{
			if (project == null)
				throw new ArgumentNullException ("project");

			this.project = project;
		}

		public override async Task<IReadOnlyList<FileProvider>> GetFilesAsync (FilterOptions filterOptions, CancellationToken cancellationToken)
		{
			var results = new List<FileProvider> ();
			if (IdeApp.Workspace.IsOpen) {
				var alreadyVisited = new HashSet<string> ();
				var conf = project.DefaultConfiguration?.Selector;
				foreach (ProjectFile file in await project.GetSourceFilesAsync (conf)) {
					if ((file.Flags & ProjectItemFlags.Hidden) == ProjectItemFlags.Hidden)
						continue;
					if (!filterOptions.IncludeCodeBehind && file.Subtype == Subtype.Designer)
						continue;
					if (!filterOptions.NameMatches (file.Name))
						continue;
					if (!IdeServices.DesktopService.GetFileIsText (file.Name))
						continue;
					if (!alreadyVisited.Add (file.FilePath.FullPath))
						continue;
					results.Add (new FileProvider (file.Name, project));
				}
			}
			return results;
		}

		public override string GetDescription (FilterOptions filterOptions, string pattern, string replacePattern)
		{
			if (replacePattern == null)
				return GettextCatalog.GetString ("Looking for '{0}' in project '{1}'", pattern, project.Name);
			return GettextCatalog.GetString ("Replacing '{0}' in project '{1}'", pattern, project.Name);
		}
	}

	class AllOpenFilesScope : Scope
	{
		public override int GetTotalWork (FilterOptions filterOptions)
		{
			return IdeApp.Workbench.Documents.Count;
		}

		public override Task<IReadOnlyList<FileProvider>> GetFilesAsync (FilterOptions filterOptions, CancellationToken cancellationToken)
		{
			var results = new List<FileProvider> ();
			foreach (Document document in IdeApp.Workbench.Documents) {
				monitor.Log.WriteLine (GettextCatalog.GetString ("Looking in '{0}'", document.FileName));
				if (!filterOptions.NameMatches (document.FileName))
					continue;
				var textBuffer = document.GetContent<ITextBuffer> ();
				if (textBuffer != null) {
					yield return new OpenFileProvider (textBuffer, document.Owner as Project, document.FileName);
				} else {
					yield return new FileProvider (document.FileName, document.Owner as Project);
				}
			}
			return EmptyFileProviderTask;
		}

		public override string GetDescription (FilterOptions filterOptions, string pattern, string replacePattern)
		{
			if (replacePattern == null)
				return GettextCatalog.GetString ("Looking for '{0}' in all open documents", pattern);
			return GettextCatalog.GetString ("Replacing '{0}' in all open documents", pattern);
		}
	}

	class DirectoryScope : Scope
	{
		readonly string path;
		readonly bool recurse;

		public override PathMode PathMode {
			get { return PathMode.Absolute; }
		}

		[Obsolete ("Unused - will be removed")]
		public bool IncludeHiddenFiles {
			get;
			set;
		}

		FileProvider[] fileNames;
		public override int GetTotalWork (FilterOptions filterOptions)
		{
			EnsureFileNamesLoaded (filterOptions);
			return fileNames.Length;
		}

		private void EnsureFileNamesLoaded (FilterOptions filterOptions)
		{
			if (fileNames != null)
				return;
			fileNames = GetFileNames (filterOptions).Select (file => new FileProvider (file)).ToArray ();
		}

		public DirectoryScope (string path, bool recurse)
		{
			this.path = path;
			this.recurse = recurse;
		}

		public override bool ValidateSearchOptions (FilterOptions filterOptions)
		{
			if (!Directory.Exists(path)) {
				MessageService.ShowError (string.Format (GettextCatalog.GetString ("Directory not found: {0}"), path));
				return false;
			}
			return true;
		}

		IEnumerable<string> GetFileNames (FilterOptions filterOptions)
		{
			if (string.IsNullOrEmpty (path))
				yield break;
			var directoryStack = new Stack<string> ();
			directoryStack.Push (path);

			while (directoryStack.Count > 0) {
				var curPath = directoryStack.Pop ();
				if (!Directory.Exists (curPath))
					yield break;
				try {
					var readPermission = new FileIOPermission(FileIOPermissionAccess.Read, curPath);
					readPermission.Demand ();
				} catch (Exception e) {
					LoggingService.LogError ("Can't access path " + curPath, e);
					yield break;
				}

				foreach (string fileName in Directory.EnumerateFiles (curPath, "*")) {
					if (Platform.IsWindows) {
						var attr = File.GetAttributes (fileName);
						if (attr.HasFlag (FileAttributes.Hidden))
							continue;
					}
					if (Path.GetFileName (fileName).StartsWith (".", StringComparison.Ordinal))
						continue;
					if (!filterOptions.NameMatches (fileName))
						continue;
					if (!IdeServices.DesktopService.GetFileIsText (fileName))
						continue;
					yield return fileName;
				}

				if (recurse) {
					foreach (string directoryName in Directory.EnumerateDirectories (curPath)) {
						if (Platform.IsWindows) {
							var attr = File.GetAttributes (directoryName);
							if (attr.HasFlag (FileAttributes.Hidden))
								continue;
						}
						if (Path.GetFileName (directoryName).StartsWith (".", StringComparison.Ordinal))
							continue;
						directoryStack.Push (directoryName);
					}
				}

			}
		}

		public override Task<IReadOnlyList<FileProvider>> GetFilesAsync (FilterOptions filterOptions, CancellationToken cancellationToken)
		{
			EnsureFileNamesLoaded (filterOptions);
			return Task.FromResult<IReadOnlyList<FileProvider>> (fileNames);
		}

		public override string GetDescription (FilterOptions filterOptions, string pattern, string replacePattern)
		{
			if (replacePattern == null)
				return GettextCatalog.GetString ("Looking for '{0}' in directory '{1}'", pattern, path);
			return GettextCatalog.GetString ("Replacing '{0}' in directory '{1}'", pattern, path);
		}
	}
}
