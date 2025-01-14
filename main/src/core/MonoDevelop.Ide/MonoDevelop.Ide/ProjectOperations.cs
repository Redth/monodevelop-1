//
// ProjectOperations.cs
//
// Author:
//   Lluis Sanchez Gual
//
// Copyright (C) 2005 Novell, Inc (http://www.novell.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MonoDevelop.Components;
using MonoDevelop.Core;
using MonoDevelop.Core.Execution;
using MonoDevelop.Core.Instrumentation;
using MonoDevelop.Core.Text;
using MonoDevelop.Ide.Editor;
using MonoDevelop.Ide.Gui;
using MonoDevelop.Ide.Gui.Dialogs;
using MonoDevelop.Ide.ProgressMonitoring;
using MonoDevelop.Ide.Projects;
using MonoDevelop.Ide.Tasks;
using MonoDevelop.Ide.TypeSystem;
using MonoDevelop.Projects;
using MonoDevelop.Projects.MSBuild;
using ExecutionContext = MonoDevelop.Projects.ExecutionContext;
using MonoDevelop.Ide.Gui.Documents;
using MonoDevelop.Ide.Projects.OptionPanels;

namespace MonoDevelop.Ide
{
	/// <summary>
	/// This is the basic interface to the workspace.
	/// </summary>
	[DefaultServiceImplementation]
	public partial class ProjectOperations: Service
	{
		static AsyncOperation<BuildResult> DefaultBuildOperation = new AsyncOperation<BuildResult> (Task.FromResult (BuildResult.CreateSuccess ()), null);
		AsyncOperation<BuildResult> currentBuildOperation = DefaultBuildOperation;
		MultipleAsyncOperation currentRunOperation = MultipleAsyncOperation.CompleteMultipleOperation;
		IBuildTarget currentBuildOperationOwner;
		List<IBuildTarget> currentRunOperationOwners = new List<IBuildTarget> ();
		RootWorkspace workspace;

		SelectReferenceDialog selDialog = null;
		
		internal ProjectOperations ()
		{
		}

		protected override async Task OnInitialize (ServiceProvider serviceProvider)
		{
			workspace = await serviceProvider.GetService<RootWorkspace> ();
			workspace.WorkspaceItemUnloaded += OnWorkspaceItemUnloaded;
			workspace.ItemUnloading += IdeAppWorkspaceItemUnloading;
			await Task.WhenAll (new Task [] {
				serviceProvider.GetService<DocumentManager> (),
				serviceProvider.GetService<ProgressMonitorManager> (),
				serviceProvider.GetService<TaskService> ()
			});
		}

		protected override Task OnDispose ()
		{
			workspace.WorkspaceItemUnloaded -= OnWorkspaceItemUnloaded;
			workspace.ItemUnloading -= IdeAppWorkspaceItemUnloading;
			return base.OnDispose ();
		}

		public Project CurrentSelectedProject {
			get {
				return workspace.CurrentSelectedProject;
			}
		}
		
		public Solution CurrentSelectedSolution {
			get {
				return workspace.CurrentSelectedSolution;
			}
		}
		
		public IBuildTarget CurrentSelectedBuildTarget {
			get {
				return workspace.CurrentSelectedBuildTarget;
			}
		}
		
		public WorkspaceObject CurrentSelectedObject {
			get {
				return workspace.CurrentSelectedObject;
			}
		}

		public WorkspaceItem CurrentSelectedWorkspaceItem {
			get {
				return workspace.CurrentSelectedWorkspaceItem;
			}
			set {
				workspace.CurrentSelectedWorkspaceItem = value;
			}
		}
		
		public SolutionFolderItem CurrentSelectedSolutionItem {
			get {
				return workspace.CurrentSelectedSolutionItem;
			}
			set {
				workspace.CurrentSelectedSolutionItem = value;
			}
		}
		
		public object CurrentSelectedItem {
			get {
				return workspace.CurrentSelectedItem;
			}
			set {
				workspace.CurrentSelectedItem = value;
			}
		}
		
		public AsyncOperation CurrentBuildOperation {
			get { return currentBuildOperation; }
		}
		
		public AsyncOperation CurrentRunOperation {
			get { return currentRunOperation; }
			set { AddRunOperation (value); }
		}

		void ResetCurrentBuildOperation ()
		{
			currentBuildOperation = DefaultBuildOperation;
			currentBuildOperationOwner = null;
		}

		public void AddRunOperation (AsyncOperation runOperation)
		{
			if (runOperation == null)
				return;
			if (runOperation.IsCompleted)//null or complete doesn't change anything, just ignore
				return;
			if (currentRunOperation.IsCompleted) {//if MultipleAsyncOperations is complete, we can't just restart Task.. start new one
				currentRunOperation = new MultipleAsyncOperation ();
				currentRunOperation.AddOperation (runOperation);
				OnCurrentRunOperationChanged (EventArgs.Empty);
			} else {//Some process is already running... attach this one to it...
				currentRunOperation.AddOperation (runOperation);
			}
		}

		public bool IsBuilding (WorkspaceObject ob)
		{
			var owner = currentBuildOperationOwner as WorkspaceObject;
			return owner != null && !currentBuildOperation.IsCompleted && ContainsTarget (ob, owner);
		}

		public bool IsRunning (WorkspaceObject target)
		{
			foreach (var currentRunOperationOwner in currentRunOperationOwners) {
				var owner = currentRunOperationOwner as WorkspaceObject;
				if (owner != null && !currentRunOperation.IsCompleted && ContainsTarget (target, owner))
					return true;
			}
			return false;
		}
		
		internal static bool ContainsTarget (WorkspaceObject owner, WorkspaceObject target)
		{
			if (owner == target)
				return true;
			else if (target is RootWorkspace)
				return ContainsTarget (owner, IdeServices.ProjectOperations.CurrentSelectedSolution);
			else if (owner is WorkspaceItem)
				return ((WorkspaceItem)owner).ContainsItem (target);
			return false;
		}

		public bool CanJumpToDeclaration (Microsoft.CodeAnalysis.ISymbol symbol)
		{
			if (symbol == null)
				return false;
			switch (symbol.Kind) {
			case Microsoft.CodeAnalysis.SymbolKind.Local:
			case Microsoft.CodeAnalysis.SymbolKind.Parameter:
			case Microsoft.CodeAnalysis.SymbolKind.NamedType:
			case Microsoft.CodeAnalysis.SymbolKind.Method:
			case Microsoft.CodeAnalysis.SymbolKind.Field:
			case Microsoft.CodeAnalysis.SymbolKind.Property:
			case Microsoft.CodeAnalysis.SymbolKind.Event:
			case Microsoft.CodeAnalysis.SymbolKind.Label:
			case Microsoft.CodeAnalysis.SymbolKind.TypeParameter:
			case Microsoft.CodeAnalysis.SymbolKind.RangeVariable:
				return true;
			}
			return false;
		}

		[Obsolete]
		static MonoDevelop.Ide.FindInFiles.SearchResult GetJumpTypePartSearchResult (Microsoft.CodeAnalysis.ISymbol part, Microsoft.CodeAnalysis.Location location)
		{
			var provider = new MonoDevelop.Ide.FindInFiles.FileProvider (location.SourceTree.FilePath);
			var doc = TextEditorFactory.CreateNewDocument ();
			doc.Text = provider.ReadString ().ReadToEnd ();
			int position = location.SourceSpan.Start;
			while (position + part.Name.Length < doc.Length) {
				if (doc.GetTextAt (position, part.Name.Length) == part.Name)
					break;
				position++;
			}
			return new MonoDevelop.Ide.FindInFiles.SearchResult (provider, position, part.Name.Length);
		}

		public async void JumpTo (Microsoft.CodeAnalysis.ISymbol symbol, Microsoft.CodeAnalysis.Location location, WorkspaceObject project = null)
		{
			if (location == null)
				return;
			if (location.IsInMetadata) {
				string fileName = null;
				var dn = project as DotNetProject;
				if (dn == null)
					return;
				var metadataDllName = location.MetadataModule.Name;
				if (metadataDllName == "CommonLanguageRuntimeLibrary")
					metadataDllName = "corlib.dll";
				foreach (var assembly in await dn.GetReferencedAssemblies (workspace.ActiveConfiguration)) {
					if (assembly.FilePath.ToString ().IndexOf (metadataDllName, StringComparison.Ordinal) > 0) {
						fileName = dn.GetAbsoluteChildPath (assembly.FilePath);
						break;
					}
				}
				if (fileName == null)
					return;
				var doc = await IdeServices.DocumentManager.OpenDocument (new FileOpenInformation (fileName, project as Project));

				if (doc != null) {
					doc.RunWhenLoaded (delegate {
						var handler = doc.GetContent<MonoDevelop.Ide.Gui.Content.IOpenNamedElementHandler> ();
						if (handler != null)
							handler.Open (symbol);
					});
				}

				return;
			}
			var filePath = location.SourceTree.FilePath;
			var offset = location.SourceSpan.Start;
			if (project is SolutionFolderItem item && item.ParentSolution != null) {
				string projectedName;
				int projectedOffset;
				if (IdeServices.TypeSystemService.GetWorkspace (item.ParentSolution).TryGetOriginalFileFromProjection (filePath, offset, out projectedName, out projectedOffset)) {
					filePath = projectedName;
					offset = projectedOffset;
				}
			}
			await IdeServices.DocumentManager.OpenDocument (new FileOpenInformation (filePath, project as Project) {
				Offset = offset
			});
		}
		
		public void JumpToDeclaration (Microsoft.CodeAnalysis.ISymbol symbol, WorkspaceObject project = null, bool askIfMultipleLocations = true)
		{
			if (symbol == null)
				throw new ArgumentNullException ("symbol");
			var locations = symbol.Locations;
			
			if (askIfMultipleLocations && locations.Length > 1) {
				using (var monitor = IdeServices.ProgressMonitorManager.GetSearchProgressMonitor (true, true)) {
					foreach (var part in locations) {
						if (monitor.CancellationToken.IsCancellationRequested)
							return;
						monitor.ReportResult (GetJumpTypePartSearchResult (symbol, part));
					}
				}
				return;
			}
			JumpTo (symbol, locations.FirstOrDefault (), project);
		}

		public async void JumpToMetadata (string metadataDllName, string documentationCommentId, Project project = null, bool openInPublicOnlyMode = true)
		{
			if (metadataDllName == null)
				throw new ArgumentNullException ("metadataDllName");
			if (documentationCommentId == null)
				throw new ArgumentNullException ("documentationCommentId");
			string fileName = metadataDllName;
			if (metadataDllName == "CommonLanguageRuntimeLibrary")
				metadataDllName = "corlib.dll";
			var dn = project as DotNetProject;
			if (dn != null) {
				foreach (var assembly in await dn.GetReferencedAssemblies (workspace.ActiveConfiguration)) {
					if (assembly.FilePath.ToString ().IndexOf(metadataDllName, StringComparison.Ordinal) > 0) {
						fileName = dn.GetAbsoluteChildPath (assembly.FilePath);
						break;
					}
				}
			}
			if (fileName == null || !File.Exists (fileName))
				return;
			var doc = await IdeServices.DocumentManager.OpenDocument (new FileOpenInformation (fileName));
			if (doc != null) {
				doc.RunWhenLoaded (delegate {
					var handler = doc.GetContent<MonoDevelop.Ide.Gui.Content.IOpenNamedElementHandler> ();
					if (handler != null)
						handler.Open (documentationCommentId, openInPublicOnlyMode);
				});
			}
		}

		public async void RenameItem (IWorkspaceFileObject item, string newName)
		{
			ProjectOptionsDialog.RenameItem (item, newName);
			if (item is SolutionFolderItem) {
				await SaveAsync (((SolutionFolderItem)item).ParentSolution);
			} else {
				await workspace.SaveAsync ();
				workspace.SavePreferences ();
			}
		}
		
		public void Export (Solution item)
		{
			Export (item, null);
		}
		
		public async void Export (IMSBuildFileObject item, MSBuildFileFormat format)
		{
			ExportSolutionDialog dlg = null;
			try {
				dlg = new ExportSolutionDialog (item, format);

				if (MessageService.RunCustomDialog (dlg) == (int) Gtk.ResponseType.Ok) {
					using (ProgressMonitor monitor = IdeServices.ProgressMonitorManager.GetToolOutputProgressMonitor (true)) {
						await Services.ProjectService.Export (monitor, item.FileName, dlg.TargetFolder, dlg.Format);
					}
				}
			} finally {
				dlg?.Destroy ();
				dlg?.Dispose ();
			}
		}
		
		public Task SaveAsync (IEnumerable<SolutionItem> entries)
		{
			List<IWorkspaceFileObject> items = new List<IWorkspaceFileObject> ();
			foreach (IWorkspaceFileObject it in entries)
				items.Add (it);
			return SaveAsync (items);
		}
		
		public Task SaveAsync (SolutionItem entry)
		{
			return SaveAsyncInternal (entry);
		}

		async Task SaveAsyncInternal (SolutionItem entry)
		{
			if (!entry.FileFormat.CanWriteFile (entry)) {
				var itemContainer = (IMSBuildFileObject) GetContainer (entry);
				if (SelectValidFileFormat (itemContainer))
					await SaveAsync (itemContainer);
				return;
			}
			
			if (!AllowSave (entry))
				return;
			
			ProgressMonitor monitor = IdeServices.ProgressMonitorManager.GetSaveProgressMonitor (true);
			try {
				await entry.SaveAsync (monitor);
				monitor.ReportSuccess (GettextCatalog.GetString ("Project saved."));
			} catch (Exception ex) {
				monitor.ReportError (GettextCatalog.GetString ("Save failed."), ex);
			} finally {
				monitor.Dispose ();
			}
		}
		
		public Task SaveAsync (Solution item)
		{
			return SaveAsyncInternal (item);
		}

		async Task SaveAsyncInternal (Solution item)
		{
			if (!item.FileFormat.CanWriteFile (item)) {
				if (!SelectValidFileFormat (item))
					return;
			}
			
			if (!AllowSave (item))
				return;
			
			ProgressMonitor monitor = IdeServices.ProgressMonitorManager.GetSaveProgressMonitor (true);
			try {
				await item.SaveAsync (monitor);
				monitor.ReportSuccess (GettextCatalog.GetString ("Solution saved."));
			} catch (Exception ex) {
				monitor.ReportError (GettextCatalog.GetString ("Save failed."), ex);
			} finally {
				monitor.Dispose ();
			}
		}
		
		public Task SaveAsync (IEnumerable<IWorkspaceFileObject> items)
		{
			return SaveAsyncInternal (items);
		}

		async Task SaveAsyncInternal (IEnumerable<IWorkspaceFileObject> items)
		{
			int count = items.Count ();
			if (count == 0)
				return;
			
			// Verify that the file format for each item is still valid
			
			HashSet<IWorkspaceFileObject> fixedItems = new HashSet<IWorkspaceFileObject> ();
			HashSet<IWorkspaceFileObject> failedItems = new HashSet<IWorkspaceFileObject> ();
			
			foreach (IWorkspaceFileObject entry in items) {
				IWorkspaceFileObject itemContainer = GetContainer (entry);
				if (fixedItems.Contains (itemContainer) || failedItems.Contains (itemContainer))
					continue;
				var msf = entry as IMSBuildFileObject;
				if (msf != null && !msf.FileFormat.CanWriteFile (entry) && (itemContainer is IMSBuildFileObject)) {
					// Can't save the project using this format. Try to find a valid format for the whole solution
					if (SelectValidFileFormat ((IMSBuildFileObject) itemContainer))
						fixedItems.Add (itemContainer);
					else
						failedItems.Add (itemContainer);
				}
			}
			if (fixedItems.Count > 0)
				await SaveAsync (fixedItems);
			
			if (failedItems.Count > 0 || fixedItems.Count > 0) {
				// Some file format changes were required, and some items were saved.
				// Get a list of items not yet saved.
				List<IWorkspaceFileObject> notSavedEntries = new List<IWorkspaceFileObject> ();
				foreach (IWorkspaceFileObject entry in items) {
					IWorkspaceFileObject itemContainer = GetContainer (entry);
					if (!fixedItems.Contains (itemContainer) && !failedItems.Contains (itemContainer))
						notSavedEntries.Add (entry);
				}
				items = notSavedEntries;
			}
			
			ProgressMonitor monitor = IdeServices.ProgressMonitorManager.GetSaveProgressMonitor (true);
			try {
				var tasks = new List<Task> ();
				monitor.BeginTask (null, count);
				foreach (IWorkspaceFileObject item in items) {
					if (AllowSave (item))
						tasks.Add (item.SaveAsync (monitor).ContinueWith (t => monitor.Step(1)));
					else
						monitor.Step (1);
				}
				await Task.WhenAll (tasks);
				monitor.EndTask ();
				monitor.ReportSuccess (GettextCatalog.GetString ("Items saved."));
			} catch (Exception ex) {
				monitor.ReportError (GettextCatalog.GetString ("Save failed."), ex);
			} finally {
				monitor.Dispose ();
			}
		}
		
		public Task SaveAsync (WorkspaceObject item)
		{
			if (item is IWorkspaceFileObject)
				return SaveAsync ((IWorkspaceFileObject)item);
			if (item.ParentObject != null)
				return SaveAsync (item.ParentObject);
			return Task.FromResult (0);
		}

		async Task SaveAsync (IWorkspaceFileObject item)
		{
			if (item is SolutionItem)
				await SaveAsync ((SolutionItem) item);
			else if (item is Solution)
				await SaveAsync ((Solution)item);

			var msf = item as IMSBuildFileObject;
			if (msf != null && !msf.FileFormat.CanWriteFile (item)) {
				var ci = (IMSBuildFileObject) GetContainer (item);
				if (SelectValidFileFormat (ci))
					await SaveAsync (ci);
				return;
			}
			
			if (!AllowSave (item))
				return;
			
			ProgressMonitor monitor = IdeServices.ProgressMonitorManager.GetSaveProgressMonitor (true);
			try {
				await item.SaveAsync (monitor);
				monitor.ReportSuccess (GettextCatalog.GetString ("Item saved."));
			} catch (Exception ex) {
				monitor.ReportError (GettextCatalog.GetString ("Save failed."), ex);
			} finally {
				monitor.Dispose ();
			}
		}
		
		bool AllowSave (IWorkspaceFileObject item)
		{
			if (HasChanged (item)) {
				return MessageService.Confirm (
					GettextCatalog.GetString (
						"Some project files have been changed from outside {0}. Do you want to overwrite them?",
						BrandingService.ApplicationName
					),
					GettextCatalog.GetString (
						"Changes made in those files will be overwritten by {0}.",
						BrandingService.ApplicationName
					),
					AlertButton.OverwriteFile);
			} else {
				return true;
			}
		}
		
		bool HasChanged (IWorkspaceFileObject item)
		{
			if (item.ItemFilesChanged)
				return true;
			if (item is WorkspaceItem) {
				foreach (SolutionItem eitem in ((WorkspaceItem)item).GetAllItems<SolutionItem> ())
					if (eitem.ItemFilesChanged)
						return true;
			}
			return false;
		}

		IWorkspaceFileObject GetContainer (IWorkspaceFileObject item)
		{
			SolutionItem si = item as SolutionItem;
			if (si != null && si.ParentSolution != null)
				return si.ParentSolution;
			else
				return item;
		}
		
		bool SelectValidFileFormat (IMSBuildFileObject item)
		{
			var dlg = new SelectFileFormatDialog (item);
			try {
				if (MessageService.RunCustomDialog (dlg) == (int) Gtk.ResponseType.Ok && dlg.Format != null) {
					item.ConvertToFormat (dlg.Format);
					return true;
				}
				return false;
			} finally {
				dlg.Destroy ();
				dlg.Dispose ();
			}
		}
		
		public void MarkFileDirty (string filename)
		{
			try {
				var fi = new FileInfo (filename);
				if (fi.Exists)
					fi.LastWriteTime = DateTime.Now;
			} catch (Exception e) {
				LoggingService.LogError ("Error while marking file as dirty", e);
			}
		}
		
		public void ShowOptions (WorkspaceObject entry)
		{
			ShowOptions (entry, null);
		}
		
		public async void ShowOptions (WorkspaceObject entry, string panelId)
		{
			if (entry is SolutionItem) {
				var selectedProject = (SolutionItem) entry;
				
				var optionsDialog = new ProjectOptionsDialog (IdeApp.Workbench.RootWindow, selectedProject);
				var conf = selectedProject.GetConfiguration (workspace.ActiveConfiguration);
				optionsDialog.CurrentConfig = conf != null ? conf.Name : null;
				optionsDialog.CurrentPlatform = conf != null ? conf.Platform : null;
				try {
					if (panelId != null)
						optionsDialog.SelectPanel (panelId);
					
					if (MessageService.RunCustomDialog (optionsDialog) == (int)Gtk.ResponseType.Ok) {
						foreach (object ob in optionsDialog.ModifiedObjects) {
							if (ob is Solution) {
								await SaveAsync ((Solution)ob);
								return;
							}
						}
						await SaveAsync (selectedProject);
						workspace.SavePreferences ();
						IdeApp.Workbench.ReparseOpenDocuments ();
					}
				} finally {
					optionsDialog.Destroy ();
					optionsDialog.Dispose ();
				}
			} else if (entry is Solution) {
				Solution solution = (Solution) entry;
				
				var optionsDialog = new CombineOptionsDialog (IdeApp.Workbench.RootWindow, solution);
				optionsDialog.CurrentConfig = workspace.ActiveConfigurationId;
				try {
					if (panelId != null)
						optionsDialog.SelectPanel (panelId);
					if (MessageService.RunCustomDialog (optionsDialog) == (int) Gtk.ResponseType.Ok) {
						await SaveAsync (solution);
						await workspace.SavePreferences (solution);
					}
				} finally {
					optionsDialog.Destroy ();
					optionsDialog.Dispose ();
				}
			}
			else {
				ItemOptionsDialog optionsDialog = new ItemOptionsDialog (IdeApp.Workbench.RootWindow, entry);
				try {
					if (panelId != null)
						optionsDialog.SelectPanel (panelId);
					if (MessageService.RunCustomDialog (optionsDialog) == (int) Gtk.ResponseType.Ok) {
						if (entry is IWorkspaceFileObject)
							await SaveAsync ((IWorkspaceFileObject) entry);
						else {
							SolutionFolderItem si = entry as SolutionFolderItem;
							if (si.ParentSolution != null)
								await SaveAsync (si.ParentSolution);
						}
						workspace.SavePreferences ();
					}
				} finally {
					optionsDialog.Destroy ();
					optionsDialog.Dispose ();
				}
			}
		}

		public async void ShowRunConfiguration (Solution solution, MultiItemSolutionRunConfiguration runConfiguration)
		{
			var optionsDialog = new CombineOptionsDialog (IdeApp.Workbench.RootWindow, solution);
			optionsDialog.CurrentConfig = IdeApp.Workspace.ActiveConfigurationId;
			try {
				optionsDialog.SelectPanel ("Run");
				if (runConfiguration != null) {
					void shownCallback (object sender, EventArgs args)
					{
						var panel = optionsDialog.GetPanel<SolutionRunConfigurationsPanel> ("General");
						if (panel != null) {
							panel.ShowConfiguration (runConfiguration);
						}
						optionsDialog.Shown -= shownCallback;
					}

					optionsDialog.Shown += shownCallback;
				}

				if (MessageService.RunCustomDialog (optionsDialog) == (int)Gtk.ResponseType.Ok) {
					await SaveAsync (solution);
					await IdeApp.Workspace.SavePreferences (solution);
				}
			} finally {
				optionsDialog.Destroy ();
				optionsDialog.Dispose ();
			}
		}

		public Task<bool> NewSolution ()
		{
			return NewSolution (null);
		}

		public Task<bool> NewSolution (string defaultTemplate)
		{
			return NewSolution (defaultTemplate, true);
		}

		public async Task<bool> NewSolution (string defaultTemplate, bool showTemplateSelection)
		{
			if (!await IdeApp.Workbench.SaveAllDirtyFiles ())
				return false;

			IdeApp.Workbench.EnsureLayout ();
			var newProjectDialog = new NewProjectDialogController ();
			newProjectDialog.OpenSolution = true;
			newProjectDialog.SelectedTemplateId = defaultTemplate;
			newProjectDialog.ShowTemplateSelection = showTemplateSelection;
			return newProjectDialog.Show ();
		}
		
		public Task<WorkspaceItem> AddNewWorkspaceItem (Workspace parentWorkspace)
		{
			return AddNewWorkspaceItem (parentWorkspace, null);
		}
		
		public async Task<WorkspaceItem> AddNewWorkspaceItem (Workspace parentWorkspace, string defaultItemId)
		{
			var newProjectDialog = new NewProjectDialogController ();
			newProjectDialog.BasePath = parentWorkspace.BaseDirectory;
			newProjectDialog.SelectedTemplateId = defaultItemId;
			newProjectDialog.ParentWorkspace = parentWorkspace;

			if (newProjectDialog.Show () && newProjectDialog.NewItem != null) {
				parentWorkspace.Items.Add ((WorkspaceItem)newProjectDialog.NewItem);
				await SaveAsync ((WorkspaceObject)parentWorkspace);
				return (WorkspaceItem)newProjectDialog.NewItem;
			}
			return null;
		}
		
		public async Task<WorkspaceItem> AddWorkspaceItem (Workspace parentWorkspace)
		{
			WorkspaceItem res = null;
			
			var dlg = new SelectFileDialog () {
				Action = FileChooserAction.Open,
				CurrentFolder = parentWorkspace.BaseDirectory,
				SelectMultiple = false,
			};
		
			dlg.AddAllFilesFilter ();
			dlg.DefaultFilter = dlg.AddFilter (GettextCatalog.GetString ("Solution Files"), "*.mds", "*.sln");
			
			if (dlg.Run ()) {
				try {
					if (WorkspaceContainsWorkspaceItem (parentWorkspace, dlg.SelectedFile)) {
						MessageService.ShowMessage (GettextCatalog.GetString ("The workspace already contains '{0}'.", Path.GetFileNameWithoutExtension (dlg.SelectedFile)));
						return res;
					}

					res = await AddWorkspaceItem (parentWorkspace, dlg.SelectedFile);
				} catch (Exception ex) {
					MessageService.ShowError (GettextCatalog.GetString ("The file '{0}' could not be loaded.", dlg.SelectedFile), ex);
				}
			}

			return res;
		}

		static bool WorkspaceContainsWorkspaceItem (Workspace workspace, FilePath workspaceItemFileName)
		{
			return workspace.Items.Any (existingWorkspaceItem => existingWorkspaceItem.FileName == workspaceItemFileName);
		}

		public async Task<WorkspaceItem> AddWorkspaceItem (Workspace parentWorkspace, string itemFileName)
		{
			using (ProgressMonitor monitor = IdeServices.ProgressMonitorManager.GetProjectLoadProgressMonitor (true)) {
				WorkspaceItem it = await Services.ProjectService.ReadWorkspaceItem (monitor, itemFileName);
				if (it != null) {
					parentWorkspace.Items.Add (it);
					await SaveAsync ((IWorkspaceFileObject)parentWorkspace);
				}
				return it;
			}
		}
		
		public SolutionFolderItem CreateProject (SolutionFolder parentFolder)
		{
			return CreateProject (parentFolder, null);
		}

		public SolutionFolderItem CreateProject (SolutionFolder parentFolder, string selectedTemplateId)
		{
			return CreateProject (parentFolder, selectedTemplateId, true);
		}

		public SolutionFolderItem CreateProject (SolutionFolder parentFolder, string selectedTemplateId, bool showTemplateSelection)
		{
			string basePath = parentFolder != null ? parentFolder.BaseDirectory : null;
			var newProjectDialog = new NewProjectDialogController ();
			newProjectDialog.ParentFolder = parentFolder;
			newProjectDialog.BasePath = basePath;
			newProjectDialog.SelectedTemplateId = selectedTemplateId;
			newProjectDialog.ShowTemplateSelection = showTemplateSelection;

			if (newProjectDialog.Show ()) {
				var item = newProjectDialog.NewItem as SolutionFolderItem;
				if ((item is Project) && ProjectCreated != null)
					ProjectCreated (this, new ProjectCreatedEventArgs (item as Project));
				return item;
			}
			return null;
		}

		public async Task<SolutionFolderItem> AddSolutionItem (SolutionFolder parentFolder)
		{
			SolutionFolderItem res = null;
			
			var dlg = new SelectFileDialog () {
				Action = FileChooserAction.Open,
				CurrentFolder = parentFolder.BaseDirectory,
				SelectMultiple = false,
			};
		
			dlg.AddAllFilesFilter ();
			dlg.DefaultFilter = dlg.AddFilter (GettextCatalog.GetString ("Project Files"), "*.*proj");
			
			if (dlg.Run ()) {
				if (!Services.ProjectService.IsSolutionItemFile (dlg.SelectedFile)) {
					MessageService.ShowMessage (GettextCatalog.GetString ("The file '{0}' is not a known project file format.", dlg.SelectedFile));
					return res;
				}

				if (SolutionContainsProject (parentFolder, dlg.SelectedFile)) {
					MessageService.ShowMessage (GettextCatalog.GetString ("The project '{0}' has already been added.", Path.GetFileNameWithoutExtension (dlg.SelectedFile)));
					return res;
				}

				try {
					res = await AddSolutionItem (parentFolder, dlg.SelectedFile);
				} catch (Exception ex) {
					MessageService.ShowError (GettextCatalog.GetString ("The file '{0}' could not be loaded.", dlg.SelectedFile), ex);
				}
			}
			
			if (res != null)
				await workspace.SaveAsync ();

			return res;
		}

		static bool SolutionContainsProject (SolutionFolder folder, FilePath projectFileName)
		{
			Solution solution = folder.ParentSolution;
			return solution.GetAllProjects ().Any (existingProject => existingProject.FileName == projectFileName);
		}

		public async Task<SolutionFolderItem> AddSolutionItem (SolutionFolder folder, string entryFileName)
		{
			AddEntryEventArgs args = new AddEntryEventArgs (folder, entryFileName);
			if (AddingEntryToCombine != null)
				AddingEntryToCombine (this, args);
			if (args.Cancel)
				return null;
			using (ProgressMonitor monitor = IdeServices.ProgressMonitorManager.GetProjectLoadProgressMonitor (true)) {
				return await folder.AddItem (monitor, args.FileName, true);
			}
		}

		public bool CreateProjectFile (Project parentProject, string basePath)
		{
			return CreateProjectFile (parentProject, basePath, null);
		}
		
		public bool CreateProjectFile (Project parentProject, string basePath, string selectedTemplateId)
		{
			using (var nfd = new NewFileDialog (parentProject, basePath)) {
				if (selectedTemplateId != null)
					nfd.SelectTemplate (selectedTemplateId);
				return MessageService.ShowCustomDialog (nfd) == (int)Gtk.ResponseType.Ok;
			}
		}

		public bool CreateSolutionFolderFile (SolutionFolder parentSolutionFolder,string selectedTemplateId = null)
		{
			using (var nfd = new NewFileDialog (null, parentSolutionFolder.BaseDirectory, parentSolutionFolder)) {
				if (selectedTemplateId != null)
					nfd.SelectTemplate (selectedTemplateId);
				return MessageService.ShowCustomDialog (nfd) == (int)Gtk.ResponseType.Ok;
			}
		}

		public bool AddReferenceToProject (DotNetProject project)
		{
			try {
				if (selDialog == null) {
					selDialog = new SelectReferenceDialog ();
					selDialog.TransientFor = MessageService.RootWindow;
				}
				
				selDialog.SetProject (project);

				if (MessageService.RunCustomDialog (selDialog) == (int)Gtk.ResponseType.Ok) {
					var newRefs = selDialog.ReferenceInformations;
					
					var editEventArgs = new EditReferencesEventArgs (project);
					foreach (var refInfo in project.References)
						if (!newRefs.Contains (refInfo))
							editEventArgs.ReferencesToRemove.Add (refInfo);

					foreach (var refInfo in selDialog.ReferenceInformations)
						if (!project.References.Contains (refInfo))
							editEventArgs.ReferencesToAdd.Add(refInfo);

					if (BeforeEditReferences != null)
						BeforeEditReferences (this, editEventArgs);

					foreach (var reference in editEventArgs.ReferencesToRemove)
						project.References.Remove (reference);

					foreach (var reference in editEventArgs.ReferencesToAdd)
						project.References.Add (reference);

					selDialog.SetProject (null);

					return editEventArgs.ReferencesToAdd.Count > 0 || editEventArgs.ReferencesToRemove.Count > 0;
				}
				else {
					selDialog.SetProject (null);
					return false;
				}
			} finally {
				selDialog.Hide ();
			}
		}
		
		public void RemoveSolutionItem (SolutionFolderItem item)
		{
			string question = GettextCatalog.GetString ("Do you really want to remove project '{0}' from '{1}'?", item.Name, item.ParentFolder.Name);
			string secondaryText = GettextCatalog.GetString ("The Remove option will remove the project from the solution, but it will not physically delete any file from disk.");
			
			SolutionItem prj = item as SolutionItem;
			if (prj == null) {
				if (MessageService.Confirm (question, AlertButton.Remove) && workspace.RequestItemUnload (item))
					RemoveItemFromSolution (prj).Ignore();
				return;
			}
			
			AlertButton delete = new AlertButton (GettextCatalog.GetString ("Delete from Disk"));
			AlertButton result = MessageService.GenericAlert (MessageService.RootWindow, Gui.Stock.Question, question, secondaryText,
			                                                  delete, AlertButton.Cancel, AlertButton.Remove);
			if (result == delete) {
				if (!workspace.RequestItemUnload (prj))
					return;
				ConfirmProjectDeleteDialog dlg = new ConfirmProjectDeleteDialog (prj);
				try {
					if (MessageService.RunCustomDialog (dlg) == (int) Gtk.ResponseType.Ok) {

						// Remove the project before removing the files to avoid unnecessary events
						RemoveItemFromSolution (prj).Ignore();

						List<FilePath> files = dlg.GetFilesToDelete ();
						using (ProgressMonitor monitor = new MessageDialogProgressMonitor (true)) {
							monitor.BeginTask (GettextCatalog.GetString ("Deleting Files..."), files.Count);
							foreach (FilePath file in files) {
								try {
									if (Directory.Exists (file))
										FileService.DeleteDirectory (file);
									else
										FileService.DeleteFile (file);
								} catch (Exception ex) {
									monitor.ReportError (GettextCatalog.GetString ("The file or directory '{0}' could not be deleted.", file), ex);
								}
								monitor.Step (1);
							}
							monitor.EndTask ();
						}
					}
				} finally {
					dlg.Destroy ();
					dlg.Dispose ();
				}
			}
			else if (result == AlertButton.Remove && workspace.RequestItemUnload (prj)) {
				RemoveItemFromSolution (prj).Ignore();
			}
		}
		
		async Task RemoveItemFromSolution (SolutionFolderItem prj)
		{
			foreach (var doc in IdeServices.DocumentManager.Documents.Where (d => d.Owner == prj).ToArray ())
				await doc.Close ();
			Solution sol = prj.ParentSolution;
			prj.ParentFolder.Items.Remove (prj);
			prj.Dispose ();
			await SaveAsync (sol);
		}
		
		/// <summary>
		/// Checks if an execution operation can start (asking the user if necessary)
		/// </summary>
		/// <returns>
		/// True if execution can continue, false otherwise
		/// </returns>
		/// <remarks>
		/// This method must be called before starting an execution operation. If there is already an execution in
		/// progress, MonoDevelop will ask confirmation for stopping the current operation.
		/// </remarks>
		public bool ConfirmExecutionOperation ()
		{
			if (!currentRunOperation.IsCompleted) {
				if (MessageService.Confirm (GettextCatalog.GetString ("An application is already running and will have to be stopped. Do you want to continue?"), AlertButton.Yes)) {
					if (currentRunOperation != null && !currentRunOperation.IsCompleted)
						currentRunOperation.Cancel ();
					return true;
				} else
					return false;
			} else
				return true;
		}

		public bool CanExecute (IBuildTarget entry)
		{
			ExecutionContext context = new ExecutionContext (Runtime.ProcessService.DefaultExecutionHandler, IdeServices.ProgressMonitorManager.ConsoleFactory, workspace.ActiveExecutionTarget);
			return CanExecute (entry, context);
		}
		
		public bool CanExecute (IBuildTarget entry, IExecutionHandler handler)
		{
			ExecutionContext context = new ExecutionContext (handler, IdeServices.ProgressMonitorManager.ConsoleFactory, workspace.ActiveExecutionTarget);
			return entry.CanExecute (context, workspace.ActiveConfiguration);
		}
		
		public bool CanExecute (IBuildTarget entry, ExecutionContext context)
		{
			return entry.CanExecute (context, workspace.ActiveConfiguration);
		}
		
		public AsyncOperation Execute (IBuildTarget entry, bool buildBeforeExecuting = true)
		{
			return Execute (entry, Runtime.ProcessService.DefaultExecutionHandler, buildBeforeExecuting);
		}
		
		public AsyncOperation Execute (IBuildTarget entry, IExecutionHandler handler, bool buildBeforeExecuting = true)
		{
			ExecutionContext context = new ExecutionContext (handler, IdeServices.ProgressMonitorManager.ConsoleFactory, workspace.ActiveExecutionTarget);
			return Execute (entry, context, buildBeforeExecuting);
		}

		public AsyncOperation Execute (IBuildTarget entry, IExecutionHandler handler, ConfigurationSelector configuration = null, RunConfiguration runConfiguration = null, bool buildBeforeExecuting = true)
		{
			ExecutionContext context = new ExecutionContext (handler, IdeServices.ProgressMonitorManager.ConsoleFactory, workspace.ActiveExecutionTarget);
			return Execute (entry, context, configuration, runConfiguration, buildBeforeExecuting);
		}

		public AsyncOperation Execute (IBuildTarget entry, ExecutionContext context, bool buildBeforeExecuting = true)
		{
			var cs = new CancellationTokenSource ();
			return new AsyncOperation (ExecuteAsync (entry, context, cs, workspace.ActiveConfiguration, null, buildBeforeExecuting), cs);
		}

		public AsyncOperation Execute (IBuildTarget entry, ExecutionContext context, ConfigurationSelector configuration = null, RunConfiguration runConfiguration = null, bool buildBeforeExecuting = true)
		{
			if (currentRunOperation != null && !currentRunOperation.IsCompleted) return currentRunOperation;

			var cs = new CancellationTokenSource ();
			return new AsyncOperation (ExecuteAsync (entry, context, cs, configuration, runConfiguration, buildBeforeExecuting), cs);
		}

		async Task ExecuteAsync (IBuildTarget entry, ExecutionContext context, CancellationTokenSource cs, ConfigurationSelector configuration, RunConfiguration runConfiguration, bool buildBeforeExecuting)
		{
			ProjectEventMetadata eventMetadata = null;

			if (entry is Solution solution) {
				SolutionItem solutionItem = null;
				if (runConfiguration == null) {
					solutionItem = solution.StartupItem;
				} else if (runConfiguration is SingleItemSolutionRunConfiguration singleItemSolution) {
					solutionItem = singleItemSolution.Item;
				}

				if (solutionItem != null) {
					eventMetadata = solutionItem.CreateProjectEventMetadata (configuration);
				}
			} else if (entry is SolutionItem item) {
				eventMetadata = item.CreateProjectEventMetadata (configuration);
			}

			var metadata = new BuildAndDeployMetadata (eventMetadata);

			// CheckAndBuildForExecute may open a dialog, so track that here if it does
			metadata.BuildWithoutPrompting = IdeApp.Preferences.BuildBeforeExecuting;

			metadata.SetSuccess ();
			Counters.BuildAndDeploy.BeginTiming ("Execute", metadata);
			Counters.TrackingBuildAndDeploy = true;

			if (configuration == null)
				configuration = workspace.ActiveConfiguration;
			
			var bth = context.ExecutionHandler as IConfigurableExecutionHandler;
			var rt = entry as IRunTarget;
			if (bth != null && rt != null) {
				var h = await bth.Configure (rt, context, configuration, runConfiguration);
				if (h == null) {
					metadata.SetFailure ();
					Counters.TrackingBuildAndDeploy = false;
					Counters.BuildAndDeploy.EndTiming ();
					return;
				}
				context = new ExecutionContext (h, context.ConsoleFactory, context.ExecutionTarget);
			}
			
			if (buildBeforeExecuting) {
				Stopwatch buildTimer = new Stopwatch ();
				buildTimer.Start ();

				if (!await CheckAndBuildForExecute (entry, context, configuration, runConfiguration)) {
					metadata.SetFailure ();
					Counters.TrackingBuildAndDeploy = false;
					Counters.BuildAndDeploy.EndTiming ();
					buildTimer.Stop ();
					return;
				}

				buildTimer.Stop ();
				metadata.BuildTime = buildTimer.ElapsedMilliseconds;
			}

			ProgressMonitor monitor = new ProgressMonitor (cs);

			var t = ExecuteSolutionItemAsync (monitor, entry, context, configuration, runConfiguration);

			var op = new AsyncOperation (t, cs);
			AddRunOperation (op);
			currentRunOperationOwners.Add (entry);

			await t;

			var error = monitor.Errors.FirstOrDefault ();
			if (error != null) {
				IdeApp.Workbench.StatusBar.ShowError (error.DisplayMessage);
				metadata.SetFailure ();
				Counters.TrackingBuildAndDeploy = false;
				Counters.BuildAndDeploy.EndTiming ();
			}
			currentRunOperationOwners.Remove (entry);
		}
		
		async Task ExecuteSolutionItemAsync (ProgressMonitor monitor, IBuildTarget entry, ExecutionContext context, ConfigurationSelector configuration, RunConfiguration runConfiguration)
		{
			try {
				OnBeforeStartProject ();
				if (entry is IRunTarget)
					await ((IRunTarget)entry).Execute (monitor, context, configuration, runConfiguration);
				else
					await entry.Execute (monitor, context, configuration);
			} catch (Exception ex) {
				monitor.ReportError (GettextCatalog.GetString ("Execution failed."), ex);
				LoggingService.LogError ("Execution failed", ex);
			} finally {
				monitor.Dispose ();
			}
		}

		public bool CanExecuteFile (string file, IExecutionHandler handler)
		{
			ExecutionContext context = new ExecutionContext (handler, IdeServices.ProgressMonitorManager.ConsoleFactory, workspace.ActiveExecutionTarget);
			return CanExecuteFile (file, context);
		}

		public bool CanExecuteFile (string file, ExecutionContext context)
		{
			var cmd = Runtime.ProcessService.CreateCommand (file);
			if (context.ExecutionHandler.CanExecute (cmd))
				return true;
			return false;
		}

		public AsyncOperation ExecuteFile (string file, IExecutionHandler handler)
		{
			ExecutionContext context = new ExecutionContext (handler, IdeServices.ProgressMonitorManager.ConsoleFactory, workspace.ActiveExecutionTarget);
			return ExecuteFile (file, context);
		}

		public AsyncOperation ExecuteFile (string file, ExecutionContext context)
		{
			var cmd = Runtime.ProcessService.CreateCommand (file);
			if (context.ExecutionHandler.CanExecute (cmd))
				return context.ExecutionHandler.Execute (cmd, context.ConsoleFactory.CreateConsole (
					OperationConsoleFactory.CreateConsoleOptions.Default.WithTitle (Path.GetFileName (file))));
			else {
				MessageService.ShowError(GettextCatalog.GetString ("No runnable executable found."));
				return AsyncOperation.CompleteOperation;
			}
		}

		public AsyncOperation Clean (IBuildTarget entry, OperationContext operationContext = null)
		{
			if (currentBuildOperation != null && !currentBuildOperation.IsCompleted) return currentBuildOperation;
			
			ITimeTracker tt = Counters.BuildItemTimer.BeginTiming ("Cleaning " + entry.Name);
			try {
				var cs = new CancellationTokenSource ();
				ProgressMonitor monitor = IdeServices.ProgressMonitorManager.GetCleanProgressMonitor ().WithCancellationSource (cs);

				OnStartClean (monitor, tt);

				var t = CleanAsync (entry, monitor, tt, false, operationContext);

				var op = new AsyncOperation<BuildResult> (t, cs);
				currentBuildOperation = op;
				currentBuildOperationOwner = entry;

				t.ContinueWith (ta => { ResetCurrentBuildOperation (); });
				return op;
			}
			catch {
				tt.End ();
				throw;
			}
		}
		
		async Task<BuildResult> CleanAsync (IBuildTarget entry, ProgressMonitor monitor, ITimeTracker tt, bool isRebuilding, OperationContext operationContext)
		{
			BuildResult res = null;
			try {
				tt.Trace ("Cleaning item");
				res = await entry.Clean (monitor, workspace.ActiveConfiguration, InitOperationContext (entry, operationContext));
			} catch (Exception ex) {
				monitor.ReportError (GettextCatalog.GetString ("Clean failed."), ex);
			} finally {
				tt.Trace ("Done cleaning");
			}
			
			if (isRebuilding) {
				if (res.HasErrors) {
					CleanDone (monitor, res, entry, tt);
				} else if (EndClean != null) {
					OnEndClean (monitor, tt);
				}
			} else {
				CleanDone (monitor, res, entry, tt);
			}
			return res;
		}

		void CleanDone (ProgressMonitor monitor, BuildResult result, IBuildTarget entry, ITimeTracker tt)
		{
			tt.Trace ("Begin reporting clean result");
			try {
				if (result != null) {
					monitor.Log.WriteLine ();

					var msg = GettextCatalog.GetString (
							"Clean: {0} succeeded, {1} failed, {2} up-to-date, {3} skipped",
							result.SuccessfulBuildCount, result.FailedBuildCount, result.UpToDateBuildCount, result.SkippedBuildCount
						);
					monitor.Log.WriteLine ( "========== " + msg + " ==========");

					tt.Trace ("Updating task service");
				
					ReportErrors (result);

					tt.Trace ("Reporting result");

					string errorString = GettextCatalog.GetPluralString ("{0} error", "{0} errors", result.ErrorCount, result.ErrorCount);
					string warningString = GettextCatalog.GetPluralString ("{0} warning", "{0} warnings", result.WarningCount, result.WarningCount);

					if (monitor.CancellationToken.IsCancellationRequested) {
						monitor.ReportError (GettextCatalog.GetString ("Clean canceled."), null);
					} else if (result.ErrorCount == 0 && result.WarningCount == 0 && result.FailedBuildCount == 0) {
						monitor.ReportSuccess (GettextCatalog.GetString ("Clean successful."));
					} else if (result.ErrorCount == 0 && result.WarningCount > 0) {
						monitor.ReportWarning (GettextCatalog.GetString ("Clean: ") + errorString + ", " + warningString);
					} else if (result.ErrorCount > 0) {
						monitor.ReportError (GettextCatalog.GetString ("Clean: ") + errorString + ", " + warningString, null);
					} else {
						monitor.ReportError (GettextCatalog.GetString ("Clean failed."), null);
					}
				}

				OnEndClean (monitor, tt);

				tt.Trace ("Showing results pad");

				ShowErrorsPadIfNecessary ();

			} finally {
				monitor.Dispose ();
				tt.End ();
			}
		}

		TaskListEntry[] ReportErrors (BuildResult result)
		{
			var tasks = new TaskListEntry [result.Errors.Count];
			for (int n = 0; n < tasks.Length; n++) {
				tasks [n] = new TaskListEntry (result.Errors [n]);
				tasks [n].Owner = this;
			}

			IdeServices.TaskService.Errors.AddRange (tasks);
			IdeServices.TaskService.Errors.ResetLocationList ();
			if (IdeApp.IsInitialized)
				IdeApp.Workbench.ActiveLocationList = IdeServices.TaskService.Errors;
			return tasks;
		}

		void ShowErrorsPadIfNecessary ()
		{
			try {
				Pad errorsPad = IdeApp.Workbench.GetPad<MonoDevelop.Ide.Gui.Pads.ErrorListPad> ();
				switch (IdeApp.Preferences.ShowErrorPadAfterBuild.Value) {
				case BuildResultStates.Always:
					if (!errorsPad.Visible)
						errorsPad.IsOpenedAutomatically = true;
					errorsPad.Visible = true;
					errorsPad.BringToFront ();
					break;
				case BuildResultStates.OnErrors:
					if (IdeServices.TaskService.Errors.Any (task => task.Severity == TaskSeverity.Error))
						goto case BuildResultStates.Always;
					break;
				case BuildResultStates.OnErrorsOrWarnings:
					if (IdeServices.TaskService.Errors.Any (task => task.Severity == TaskSeverity.Error || task.Severity == TaskSeverity.Warning))
						goto case BuildResultStates.Always;
					break;
				}
			} catch { }
		}

		public AsyncOperation<BuildResult> Rebuild (Project project, ProjectOperationContext operationContext = null)
		{
			return Rebuild ((IBuildTarget)project, operationContext);
		}

		public AsyncOperation<BuildResult> Rebuild (IBuildTarget entry, OperationContext operationContext = null)
		{
			if (currentBuildOperation != null && !currentBuildOperation.IsCompleted) return currentBuildOperation;

			var cs = new CancellationTokenSource ();
			ProgressMonitor monitor = IdeServices.ProgressMonitorManager.GetRebuildProgressMonitor ().WithCancellationSource (cs);

			var t = RebuildAsync (entry, monitor, operationContext);

			var op = new AsyncOperation<BuildResult> (t, cs);
			currentBuildOperation = op;
			currentBuildOperationOwner = entry;

			t.ContinueWith (ta => { ResetCurrentBuildOperation (); });
			return op;
		}
		
		async Task<BuildResult> RebuildAsync (IBuildTarget entry, ProgressMonitor monitor, OperationContext operationContext)
		{
			ITimeTracker tt = Counters.BuildItemTimer.BeginTiming ("Rebuilding " + entry.Name);
			try {
				OnStartClean (monitor, tt);

				monitor.BeginTask (GettextCatalog.GetString ("Rebuilding..."), 2);
				monitor.BeginStep (GettextCatalog.GetString ("Rebuilding... (Clean)"));

				var res = await CleanAsync (entry, monitor, tt, true, operationContext);
				monitor.EndStep ();
				if (res.HasErrors) {
					tt.End ();
					monitor.Dispose ();
					return res;
				}
				if (StartBuild != null) {
					BeginBuild (monitor, tt, true);
				}
				monitor.BeginStep (GettextCatalog.GetString ("Rebuilding... (Build)"));
				return await BuildSolutionItemAsync (entry, monitor, tt, operationContext:operationContext);
			} finally {
				tt.End ();
			}
		}

		internal static IBuildTarget[] GetBuildTargetsForExecution (IBuildTarget executionTarget, RunConfiguration runConfiguration)
		{
			if (executionTarget is Solution sol) {
				if (runConfiguration == null) {
					runConfiguration = sol.StartupConfiguration;
				}
				if (runConfiguration is SingleItemSolutionRunConfiguration src) {
					return new [] { src.Item };
				}
				if (runConfiguration is MultiItemSolutionRunConfiguration mrc) {
					var buildTargets = new IBuildTarget [mrc.Items.Count];
					int i = 0;
					foreach (var item in mrc.Items) {
						buildTargets [i++] = item.SolutionItem;
					}
					return buildTargets;
				}
			}
			return new [] { executionTarget };
		}

		// given a solution RunConfiguration, determine the matching project RunConfigurations
		static RunConfiguration GetProjectRunConfiguration (IRunTarget target, RunConfiguration config)
		{
			if (config is SingleItemSolutionRunConfiguration src) {
				if (src.Item == target) {
					return src.RunConfiguration;
				}
			}
			else if (config is MultiItemSolutionRunConfiguration mrc) {
				foreach (var item in mrc.Items) {
					if (item.SolutionItem == target)
						return item.RunConfiguration;
				}
			}
			return config;
		}

		Task<bool> CheckAndBuildForExecute (IBuildTarget executionTarget, ExecutionContext context, ConfigurationSelector configuration, RunConfiguration runConfiguration)
		{
			// When executing a solution we are actually going to execute the startup project(s), so we only need to build it/them
			IBuildTarget [] buildTargets = GetBuildTargetsForExecution (executionTarget, runConfiguration);

			return CheckAndBuildForExecute (
				buildTargets, configuration,
				IdeApp.Preferences.BuildBeforeExecuting, !IdeApp.Preferences.RunWithWarnings,
				(target, monitor) => {
					if (target is IRunTarget runTarget) {
						var projectRunConfig = GetProjectRunConfiguration (runTarget, runConfiguration);
						return runTarget.PrepareExecution (monitor, context, configuration, projectRunConfig);
					}
					return target.PrepareExecution (monitor, context, configuration);
				}
			);
		}

		/// <summary>
		/// Prepares projects/solutions for execution by building them and their execution dependencies if necessary.
		/// </summary>
		/// <returns>Whether the operation was successful.</returns>
		/// <param name="executionTargets">The projects and/or solution to build. If there are multiple projects, they must be in the same solution.</param>
		/// <param name="configuration">The configuration selector.</param>
		/// <param name="buildWithoutPrompting">Whether to prompt the user before building, when building is necessary.</param>
		/// <param name="cancelOnWarning">Whether to cancel the execution operation if there is a build warning.</param>
		/// <param name="createPrepareExecutionTask">
		/// May be executed in parallel with the build to perform additional
		/// preparation that does not depend on the build, such as launching a simulator.
		/// There is no guaranteed this will be executed for any target.
		/// </param>
		public async Task<bool> CheckAndBuildForExecute (
			ICollection<IBuildTarget> executionTargets, ConfigurationSelector configuration,
			bool buildWithoutPrompting = true, bool cancelOnWarning = false,
			Func<IBuildTarget, ProgressMonitor,Task> createPrepareExecutionTask = null,
			CancellationToken? token = null)
		{
			if (executionTargets.Count == 0) {
				throw new ArgumentException ("No execution targets specified", nameof (executionTargets)); ;
			}

			if (currentBuildOperation != null && !currentBuildOperation.IsCompleted) {
				var bres = await currentBuildOperation.Task;
				if (bres.HasErrors || (cancelOnWarning && bres.HasWarnings))
					return false;
			}

			//saves open documents since it may dirty the "needs building" check
			var r = await DoBeforeCompileAction ();
			if (r.Failed)
				return false;

			var executionDeps = executionTargets.SelectMany (et => et.GetExecutionDependencies ());
			IBuildTarget buildTarget = SolutionItemBuildBatch.Create (executionDeps);

			var context = new TargetEvaluationContext ();
			context.GlobalProperties.SetValue ("IsBuildingForExecution", true);

			if (!FastCheckNeedsBuild (buildTarget, configuration, context)) {
				return true;
			}

			if (!buildWithoutPrompting) {
				var ret = PromptToBuild ();
				if (ret.HasValue) {
					return ret.Value;
				}
			}

			CancellationTokenSource prepareOpTokenSource = null;

			// Building the project may take some time, so we call PrepareExecution so that the target can
			// prepare the execution while the build is in progress (for example, it could start a simulator).
			// As a simple way to avoid starvation, if there are multiple, we run them in sequence.
			bool building = true;
			Task prepareExecutionTask = null;
			if (createPrepareExecutionTask != null) {
				prepareOpTokenSource = token != null
					? CancellationTokenSource.CreateLinkedTokenSource (token.Value)
					: new CancellationTokenSource ();
				prepareExecutionTask = RunPrepareExecutionTasks ();
			}

			BuildResult result = await Build (buildTarget, token, context).Task;

			if (result.HasErrors || (cancelOnWarning && result.HasWarnings)) {
				prepareOpTokenSource?.Cancel ();
				return false;
			}

			building = false;
			if (prepareExecutionTask != null) {
				await prepareExecutionTask;
			}

			return true;

			async Task RunPrepareExecutionTasks ()
			{
				var targetsToPrepare = new Queue<IBuildTarget> (executionTargets);

				while (targetsToPrepare.Count > 0 && building) {
					var target = targetsToPrepare.Dequeue ();
					var monitor = new ProgressMonitor ().WithCancellationSource (prepareOpTokenSource);
					await createPrepareExecutionTask (target, monitor);
				}
			}
		}

		/// <summary>
		/// Prompts the user whether they want to build the project
		/// </summary>
		/// <returns>True to execute without building, false to cancel, null to build.</returns>
		static bool? PromptToBuild ()
		{
			var bBuild = new AlertButton (GettextCatalog.GetString ("Build"));
			var bRun = new AlertButton (Gtk.Stock.Execute, true);
			var res = MessageService.AskQuestion (
				GettextCatalog.GetString ("Outdated Build"),
				GettextCatalog.GetString ("The project you are executing has changed since the last time it was compiled. Do you want to continue or rebuild it?"),
				1,
				AlertButton.Cancel,
				bBuild,
				bRun);

			// This call is a workaround for bug #6907. Without it, the main monodevelop window is left it a weird
			// drawing state after the message dialog is shown. This may be a gtk/mac issue. Still under research.
			DispatchService.RunPendingEvents ();

			if (res == bRun) {
				return true;
			}

			if (res == bBuild) {
				return null;
			}

			return false;
		}

		/// <summary>
		/// Given a build target, determines whether it or its dependencies needs to be built.
		/// </summary>
		/// <param name="target">The build target to check.</param>
		/// <param name="configuration">The build configuration selector.</param>
		static bool FastCheckNeedsBuild (IBuildTarget target, ConfigurationSelector configuration, TargetEvaluationContext context)
		{
			if (FastBuildCheckDisabled ()) {
				return true;
			}

			IEnumerable<SolutionItem> items;

			switch (target) {
			case Project proj: {
					var deps = new HashSet<SolutionItem> { proj };
					CollectDependencies (proj, deps, configuration);
					items = deps;
					break;
				}
			case SolutionItemBuildBatch batch: {
					var deps = new HashSet<SolutionItem> ();
					foreach (var item in batch.Items) {
						deps.Add (item);
						CollectDependencies (item, deps, configuration);
					}
					items = deps;
					break;
				}
			case Solution sln:
				items = sln.GetAllSolutionItems ();
				break;
			default:
				return true;
			}

			foreach (var item in items) {
				if (!(item is Project p) || p.FastCheckNeedsBuild (configuration, InitOperationContext (target, context))) {
					return true;
				}
			}

			return false;
		}

		static bool FastBuildCheckDisabled ()
		{
			var env = Environment.GetEnvironmentVariable ("DisableFastUpToDateCheck");
			return !string.IsNullOrEmpty (env) && env != "0" && !env.Equals ("false", StringComparison.OrdinalIgnoreCase);
		}

		//TODO: respect solution level dependencies
		static void CollectDependencies (SolutionItem item, HashSet<SolutionItem> collected, ConfigurationSelector configuration)
		{
			foreach (var refItem in item.GetReferencedItems (configuration)) {
				if (collected.Add (refItem)) {
					CollectDependencies (refItem, collected, configuration);
				}
			}
		}
		
//		bool errorPadInitialized = false;

		public AsyncOperation<BuildResult> Build (Project project, CancellationToken? cancellationToken = null, ProjectOperationContext operationContext = null)
		{
			return Build (project, false, cancellationToken, operationContext);
		}

		public AsyncOperation<BuildResult> Build (IBuildTarget entry, CancellationToken? cancellationToken = null, OperationContext operationContext = null)
		{
			return Build (entry, false, cancellationToken, operationContext);
		}

		AsyncOperation<BuildResult> Build (IBuildTarget entry, bool skipPrebuildCheck, CancellationToken? cancellationToken = null, OperationContext operationContext = null)
		{
			if (currentBuildOperation != null && !currentBuildOperation.IsCompleted) return currentBuildOperation;

			ITimeTracker tt = Counters.BuildItemTimer.BeginTiming ("Building " + entry.Name);
			try {
				var cs = new CancellationTokenSource ();
				if (cancellationToken != null)
					cs = CancellationTokenSource.CreateLinkedTokenSource (cs.Token, cancellationToken.Value);
				ProgressMonitor monitor = IdeServices.ProgressMonitorManager.GetBuildProgressMonitor ().WithCancellationSource (cs);
				BeginBuild (monitor, tt, false);

				var t = BuildSolutionItemAsync (entry, monitor, tt, skipPrebuildCheck, operationContext);

				var op = new AsyncOperation<BuildResult> (t, cs);
				currentBuildOperation = op;
				currentBuildOperationOwner = entry;

				t.ContinueWith (ta => { ResetCurrentBuildOperation (); });
				return op;
			} catch {
				tt.End ();
				throw;
			}
		}
		
		async Task<BuildResult> BuildSolutionItemAsync (IBuildTarget entry, ProgressMonitor monitor, ITimeTracker tt, bool skipPrebuildCheck = false, OperationContext operationContext = null)
		{
			BuildResult result = null;
			try {
				if (!skipPrebuildCheck) {
					tt.Trace ("Pre-build operations");
					result = await DoBeforeCompileAction ();
				}

				//wait for any custom tools that were triggered by the save, since the build may depend on them
				await MonoDevelop.Ide.CustomTools.CustomToolService.WaitForRunningTools (monitor);

				if (skipPrebuildCheck || result.ErrorCount == 0) {
					tt.Trace ("Building item");
					result = await entry.Build (monitor, workspace.ActiveConfiguration, true, InitOperationContext (entry, operationContext));
				}
			} catch (Exception ex) {
				monitor.ReportError (GettextCatalog.GetString ("Build failed."), ex);
				if (result == null)
					result = new BuildResult ();
				result.AddError ("Build failed. See the build log for details.");
				if (result.SourceTarget == null)
					result.SourceTarget = entry;
			} finally {
				tt.Trace ("Done building");
			}

			BuildDone (monitor, result, entry, tt);	// BuildDone disposes the monitor

			return result;
		}

		/// <summary>
		/// Initializes the context to be used for build operations. It currently just initializes
		/// it with the currently selected execution target.
		/// </summary>
		static T InitOperationContext<T> (IBuildTarget target, T context) where T:OperationContext
		{
			OperationContext ctx = context;
			if (ctx == null)
				ctx = new OperationContext ();
			if (ctx.ExecutionTarget == null) {
				var item = target as SolutionItem;
				if (item != null)
					ctx.ExecutionTarget = IdeServices.Workspace.GetActiveExecutionTarget (item);
				else
					ctx.ExecutionTarget = IdeServices.Workspace.ActiveExecutionTarget;
			}
			return (T)ctx;
		}
		
		// Note: This must run in the main thread
		async Task PromptForSave (BuildResult result)
		{
			var couldNotSaveError = "The build has been aborted as the file '{0}' could not be saved";
			
			foreach (var doc in IdeServices.DocumentManager.Documents) {
				if (doc.IsDirty && doc.Owner != null) {
					if (MessageService.AskQuestion (GettextCatalog.GetString ("Save changed documents before building?"),
					                                GettextCatalog.GetString ("Some of the open documents have unsaved changes."),
					                                AlertButton.BuildWithoutSave, AlertButton.Save) == AlertButton.Save) {
						MarkFileDirty (doc.FileName);
						await doc.Save ();
						if (doc.IsDirty)
							result.AddError (string.Format (couldNotSaveError, Path.GetFileName (doc.FileName)), doc.FileName);
					} else
						break;
				}
			}
		}
		
		// Note: This must run in the main thread
		async Task SaveAllFiles (BuildResult result)
		{
			var couldNotSaveError = "The build has been aborted as the file '{0}' could not be saved";
			
			foreach (var doc in new List<MonoDevelop.Ide.Gui.Document> (IdeServices.DocumentManager.Documents)) {
				if (doc.IsDirty && doc.Owner != null) {
					await doc.Save ();
					if (doc.IsDirty) {
						doc.Select ();
						result.AddError (string.Format (couldNotSaveError, Path.GetFileName (doc.FileName)), doc.FileName);
					}
				}
			}
		}

		Task<BuildResult> DoBeforeCompileAction ()
		{
			return ApplySavePolicy ();
		}

		public async Task<BuildResult> ApplySavePolicy ()
		{
			BeforeCompileAction action = IdeApp.Preferences.BeforeBuildSaveAction;
			var result = new BuildResult ();

			switch (action) {
			case BeforeCompileAction.Nothing: break;
			case BeforeCompileAction.PromptForSave: await PromptForSave (result); break;
			case BeforeCompileAction.SaveAllFiles: await SaveAllFiles (result); break;
			default: System.Diagnostics.Debug.Assert (false); break;
			}

			return result;
		}

		void BeginBuild (ProgressMonitor monitor, ITimeTracker tt, bool isRebuilding)
		{
			tt.Trace ("Start build event");
			if (!isRebuilding) {
				IdeServices.TaskService.Errors.ClearByOwner (this);
			}
			if (StartBuild != null) {
				StartBuild (this, new BuildEventArgs (monitor, true));
			}
		}
		
		void BuildDone (ProgressMonitor monitor, BuildResult result, IBuildTarget entry, ITimeTracker tt)
		{
			TaskListEntry[] tasks = null;
			tt.Trace ("Begin reporting build result");
			try {
				if (result != null) {
					monitor.Log.WriteLine ();

					var msg = GettextCatalog.GetString (
							"Build: {0} succeeded, {1} failed, {2} up-to-date, {3} skipped",
							result.SuccessfulBuildCount, result.FailedBuildCount, result.UpToDateBuildCount, result.SkippedBuildCount
						);
					monitor.Log.WriteLine ( "========== " + msg + " ==========");
					
					tt.Trace ("Updating task service");

					tasks = ReportErrors (result);

					tt.Trace ("Reporting result");
					
					string errorString = GettextCatalog.GetPluralString("{0} error", "{0} errors", result.ErrorCount, result.ErrorCount);
					string warningString = GettextCatalog.GetPluralString("{0} warning", "{0} warnings", result.WarningCount, result.WarningCount);

					if (monitor.CancellationToken.IsCancellationRequested) {
						monitor.ReportError (GettextCatalog.GetString ("Build canceled."), null);
					} else if (result.ErrorCount == 0 && result.WarningCount == 0 && result.FailedBuildCount == 0) {
						monitor.ReportSuccess (GettextCatalog.GetString ("Build successful."));
					} else if (result.ErrorCount == 0 && result.WarningCount > 0) {
						monitor.ReportWarning(GettextCatalog.GetString("Build: ") + errorString + ", " + warningString);
					} else if (result.ErrorCount > 0) {
						monitor.ReportError(GettextCatalog.GetString("Build: ") + errorString + ", " + warningString, null);
					} else {
						monitor.ReportError(GettextCatalog.GetString("Build failed."), null);
					}
					tt.Trace ("End build event");
					OnEndBuild (monitor, result.FailedBuildCount == 0, result, entry as SolutionFolderItem);
				} else {
					tt.Trace ("End build event");
					OnEndBuild (monitor, false);
				}
				
				tt.Trace ("Showing results pad");
				
				ShowErrorsPadIfNecessary ();

				if (tasks != null) {
					TaskListEntry jumpTask = null;
					switch (IdeApp.Preferences.JumpToFirstErrorOrWarning.Value) {
					case JumpToFirst.Error:
						jumpTask = tasks.FirstOrDefault (t => t.Severity == TaskSeverity.Error && TaskStore.IsProjectTaskFile (t));
						break;
					case JumpToFirst.ErrorOrWarning:
						jumpTask = tasks.FirstOrDefault (t => (t.Severity == TaskSeverity.Error || t.Severity == TaskSeverity.Warning) && TaskStore.IsProjectTaskFile (t));
						break;
					}
					if (jumpTask != null) {
						tt.Trace ("Jumping to first result position");
						jumpTask.JumpToPosition ();
					}
				}
				
			} finally {
				monitor.Dispose ();
				tt.End ();
			}
		}
		
		public bool AddFilesToSolutionFolder (SolutionFolder folder)
		{
			var dlg = new SelectFileDialog () {
				SelectMultiple = true,
				Action = FileChooserAction.Open,
				CurrentFolder = folder.BaseDirectory,
				TransientFor = MessageService.RootWindow,
			};
			if (dlg.Run ())
				return AddFilesToSolutionFolder (folder, dlg.SelectedFiles);
			else
				return false;
		}
		
		public bool AddFilesToSolutionFolder (SolutionFolder folder, FilePath[] files)
		{
			return AddFilesToSolutionFolder (folder, files.ToStringArray ());
		}
		
		public bool AddFilesToSolutionFolder (SolutionFolder folder, string[] files)
		{
			QuestionMessage msg = new QuestionMessage ();
			AlertButton keepButton = new AlertButton (GettextCatalog.GetString ("Keep file path"));
			msg.Buttons.Add (keepButton);
			msg.Buttons.Add (AlertButton.Copy);
			msg.Buttons.Add (AlertButton.Move);
			msg.Buttons.Add (AlertButton.Cancel);
			msg.AllowApplyToAll = true;
			
			bool someAdded = false;
			
			foreach (string file in files) {
				FilePath fp = file;
				FilePath dest = folder.BaseDirectory.Combine (fp.FileName);
				
				if (!fp.IsChildPathOf (folder.BaseDirectory)) {
					msg.Text = GettextCatalog.GetString ("The file {0} is outside the folder directory. What do you want to do?", fp.FileName);
					AlertButton res = MessageService.AskQuestion (msg);
					if (res == AlertButton.Cancel)
						return someAdded;
					if (res == AlertButton.Copy) {
						FileService.CopyFile (file, dest);
						fp = dest;
					} else if (res == AlertButton.Move) {
						FileService.MoveFile (file, dest);
						fp = dest;
					}
				}

				if (folder.IsRoot) {
					// Don't allow adding files to the root folder. VS doesn't allow it
					// If there is no existing folder, create one
					folder = folder.ParentSolution.DefaultSolutionFolder;
				}

				folder.Files.Add (fp);
				someAdded = true;
			}
			return someAdded;
		}
		
		public IList<ProjectFile> AddFilesToProject (Project project, string[] files, FilePath targetDirectory)
		{
			return AddFilesToProject (project, files.ToFilePathArray (), targetDirectory);
		}
		
		public IList<ProjectFile> AddFilesToProject (Project project, FilePath[] files, FilePath targetDirectory)
		{
			return AddFilesToProject (project, files, targetDirectory, null);
		}
		
		public IList<ProjectFile> AddFilesToProject (Project project, FilePath[] files, FilePath targetDirectory,
			string buildAction)
		{
			Debug.Assert (targetDirectory.CanonicalPath == project.BaseDirectory.CanonicalPath
				|| targetDirectory.IsChildPathOf (project.BaseDirectory));
			
			var targetPaths = new FilePath[files.Length];
			for (int i = 0; i < files.Length; i++)
				targetPaths[i] = targetDirectory.Combine (files[i].FileName);
			
			return AddFilesToProject (project, files, targetPaths, buildAction);
		}

		/// <summary>
		/// Adds files to a project, potentially asking the user whether to move, copy or link the files.
		/// </summary>
		public IList<ProjectFile> AddFilesToProject (Project project, FilePath[] files, FilePath[] targetPaths,
			string buildAction)
		{
			Debug.Assert (project != null);
			Debug.Assert (files != null);
			Debug.Assert (targetPaths != null);
			Debug.Assert (files.Length == targetPaths.Length);
			
			AddAction action = AddAction.Copy;
			bool applyToAll = true;
			bool dialogShown = false;
			bool supportsLinking = !(project is MonoDevelop.Projects.SharedAssetsProjects.SharedAssetsProject);

			var confirmReplaceFileMessage = new QuestionMessage ();
			if (files.Length > 1) {
				confirmReplaceFileMessage.AllowApplyToAll = true;
				confirmReplaceFileMessage.Buttons.Add (new AlertButton (GettextCatalog.GetString ("Skip")));
			}
			confirmReplaceFileMessage.Buttons.Add (AlertButton.Cancel);
			confirmReplaceFileMessage.Buttons.Add (AlertButton.OverwriteFile);
			confirmReplaceFileMessage.DefaultButton = confirmReplaceFileMessage.Buttons.Count - 1;
			
			ProgressMonitor monitor = null;
			
			if (files.Length > 10) {
				monitor = new MessageDialogProgressMonitor (true, true, true, true, MessageService.RootWindow);
				monitor.BeginTask (GettextCatalog.GetString("Adding files..."), files.Length);
			}
			
			var newFileList = new List<ProjectFile> ();
			
			//project.AddFile (string) does linear search for duplicate file, so instead we use this HashSet and 
			//and add the ProjectFiles directly. With large project and many files, this should really help perf.
			//Also, this is a better check because we handle vpaths and links.
			//FIXME: it would be really nice if project.Files maintained these hashmaps
			var vpathsInProject = new Dictionary<FilePath, ProjectFile> ();
			var filesInProject = new Dictionary<FilePath,ProjectFile> ();

			using (monitor)
			{
				foreach (var pf in project.Files) {
					filesInProject [pf.FilePath] = pf;
					vpathsInProject [pf.ProjectVirtualPath] = pf;
				}

				for (int i = 0; i < files.Length; i++) {
					FilePath file = files[i];
					
					if (monitor != null) {
						monitor.Log.WriteLine (file);
						monitor.Step (1);
					}
					
					if (FileService.IsDirectory (file)) {
						//FIXME: warning about skipping?
						newFileList.Add (null);
						continue;
					}
					
					FilePath targetPath = targetPaths[i].CanonicalPath;
					Debug.Assert (targetPath.IsChildPathOf (project.BaseDirectory));

					ProjectFile vfile;
					var vpath = targetPath.ToRelative (project.BaseDirectory);
					if (vpathsInProject.TryGetValue (vpath, out vfile)) {
						if (vfile.IsLink) {
							MessageService.ShowWarning (GettextCatalog.GetString (
								"There is already a link in the project with the name '{0}'", vpath));
							continue;
						} else if (vfile.FilePath == file) {
							// File already exists in project.
							continue;
						}
					}
					
					string fileBuildAction = buildAction;
					if (string.IsNullOrEmpty (buildAction))
						fileBuildAction = project.GetDefaultBuildAction (targetPath);
					
					//files in the target directory get added directly in their current location without moving/copying
					if (file.CanonicalPath == targetPath) {
						if (vfile != null)
							ShowFileExistsInProjectMessage (vpath);
						else
							AddFileToFolder (newFileList, vpathsInProject, filesInProject, file, fileBuildAction);
						continue;
					}
					
					//for files outside the project directory, we ask the user whether to move, copy or link
					
					AddExternalFileDialog addExternalDialog = null;
					
					if (!dialogShown || !applyToAll) {
						addExternalDialog = new AddExternalFileDialog (file);
						if (!supportsLinking)
							addExternalDialog.DisableLinkOption ();
						if (files.Length > 1) {
							addExternalDialog.ApplyToAll = applyToAll;
							addExternalDialog.ShowApplyAll = true;
						}
						if (file.IsChildPathOf (targetPath.ParentDirectory))
							addExternalDialog.ShowKeepOption (file.ParentDirectory.ToRelative (targetPath.ParentDirectory));
						else {
							if (action == AddAction.Keep)
								action = AddAction.Copy;
							addExternalDialog.SelectedAction = action;
						}
					}
					
					try {
						if (!dialogShown || !applyToAll) {
							int response = MessageService.RunCustomDialog (addExternalDialog);
							// A dialog emits DeleteEvent rather than Cancel in response to Escape being pressed
							if (response == (int) Gtk.ResponseType.Cancel || response == (int) Gtk.ResponseType.DeleteEvent) {
								project.Files.AddRange (newFileList.Where (f => f != null));
								return newFileList;
							}
							action = addExternalDialog.SelectedAction;
							applyToAll = addExternalDialog.ApplyToAll;
							dialogShown = true;
						}
						
						if (action == AddAction.Keep) {
							if (vfile != null)
								ShowFileExistsInProjectMessage (vpath);
							else
								AddFileToFolder (newFileList, vpathsInProject, filesInProject, file, fileBuildAction);
							continue;
						}
						
						if (action == AddAction.Link) {
							if (vfile != null) {
								ShowFileExistsInProjectMessage (vpath);
								continue;
							}
							ProjectFile pf = new ProjectFile (file, fileBuildAction) {
								Link = vpath
							};
							vpathsInProject [pf.ProjectVirtualPath] = pf;
							filesInProject [pf.FilePath] = pf;
							newFileList.Add (pf);
							continue;
						}
						
						try {
							if (!Directory.Exists (targetPath.ParentDirectory))
								FileService.CreateDirectory (targetPath.ParentDirectory);

							bool? result = MoveCopyFile (file, targetPath, action == AddAction.Move, confirmReplaceFileMessage);
							if (result == true) {
								if (vfile == null) {
									// Build action may depend on file location if globs are used so check again after moving the file.
									if (string.IsNullOrEmpty (buildAction))
										fileBuildAction = project.GetDefaultBuildAction (targetPath);

									var pf = new ProjectFile (targetPath, fileBuildAction);
									vpathsInProject [pf.ProjectVirtualPath] = pf;
									filesInProject [pf.FilePath] = pf;
									newFileList.Add (pf);
								}
							} else if (result == null) {
								project.Files.AddRange (newFileList.Where (f => f != null));
								return newFileList;
							} else {
								newFileList.Add (null);
							}
						}
						catch (Exception ex) {
							MessageService.ShowError (GettextCatalog.GetString (
								"An error occurred while attempt to move/copy that file. Please check your permissions."), ex);
							newFileList.Add (null);
						}
					} finally {
						if (addExternalDialog != null) {
							addExternalDialog.Destroy ();
							addExternalDialog.Dispose ();
						}
					}
				}
			}
			project.Files.AddRange (newFileList.Where (f => f != null));
			return newFileList;
		}

		static void ShowFileExistsInProjectMessage (FilePath path)
		{
			MessageService.ShowWarning (GettextCatalog.GetString (
				"There is already a file in the project with the name '{0}'", path));
		}
		
		void AddFileToFolder (List<ProjectFile> newFileList, Dictionary<FilePath, ProjectFile> vpathsInProject, Dictionary<FilePath, ProjectFile> filesInProject, FilePath file, string fileBuildAction)
		{
			//FIXME: MD project system doesn't cope with duplicate includes - project save/load will remove the file
			ProjectFile pf;
			if (filesInProject.TryGetValue (file, out pf)) {
				var link = pf.Link;
				MessageService.ShowWarning (GettextCatalog.GetString (
					"The link '{0}' in the project already includes the file '{1}'", link, file));
				return;
			}
			pf = new ProjectFile (file, fileBuildAction);
			vpathsInProject [pf.ProjectVirtualPath] = pf;
			filesInProject [pf.FilePath] = pf;
			newFileList.Add (pf);
		}
		
		bool? MoveCopyFile (string filename, string targetFilename, bool move, QuestionMessage confirm)
		{
			if (filename != targetFilename) {
				if (File.Exists (targetFilename)) {
					confirm.Text = GettextCatalog.GetString ("The file '{0}' already exists. Do you want to replace it?",
						targetFilename);
					AlertButton result = MessageService.AskQuestion (confirm);
					if (result == AlertButton.Cancel)
						return null;
					else if (result != AlertButton.OverwriteFile)
						return false;
				}
				FileService.CopyFile (filename, targetFilename);
				if (move)
					FileService.DeleteFile (filename);
			}
			return true;
		}

		public void TransferFiles (ProgressMonitor monitor, Project sourceProject, FilePath sourcePath, Project targetProject,
								   FilePath targetPath, bool removeFromSource, bool copyOnlyProjectFiles)
		{
			TransferFilesInternal (monitor, sourceProject, sourcePath, targetProject, targetPath, removeFromSource, copyOnlyProjectFiles);
		}

		internal static void TransferFilesInternal (ProgressMonitor monitor, Project sourceProject, FilePath sourcePath, Project targetProject,
		                           FilePath targetPath, bool removeFromSource, bool copyOnlyProjectFiles)
		{
			// When transfering directories, targetPath is the directory where the source
			// directory will be transfered, including the destination directory or file name.
			// For example, if sourcePath is /a1/a2/a3 and targetPath is /b1/b2, the
			// new folder or file will be /b1/b2
			
			if (targetProject == null)
				throw new ArgumentNullException ("targetProject");

			if (!targetPath.IsChildPathOf (targetProject.BaseDirectory))
				throw new ArgumentException ("Invalid project folder: " + targetPath);

			if (sourceProject != null && !sourcePath.IsChildPathOf (sourceProject.BaseDirectory))
				throw new ArgumentException ("Invalid project folder: " + sourcePath);
				
			if (copyOnlyProjectFiles && sourceProject == null)
				throw new ArgumentException ("A source project must be specified if copyOnlyProjectFiles is True");
			
			bool sourceIsFolder = Directory.Exists (sourcePath);

			bool movingFolder = removeFromSource && sourceIsFolder && (
				!copyOnlyProjectFiles ||
				ContainsOnlyProjectFiles (sourcePath, sourceProject));

			// We need to remove all files + directories from the source project
			// but when dealing with the VCS addins we need to process only the
			// files so we do not create a 'file' in the VCS which corresponds
			// to a directory in the project and blow things up.
			List<ProjectFile> filesToRemove = null;
			List<ProjectFile> filesToMove = null;
			try {
				//get the real ProjectFiles
				if (sourceProject != null) {
					if (sourceIsFolder) {
						var virtualPath = sourcePath.ToRelative (sourceProject.BaseDirectory);
						// Grab all the child nodes of the folder we just dragged/dropped
						filesToRemove = sourceProject.Files.GetFilesInVirtualPath (virtualPath).ToList ();
						// Add the folder itself so we can remove it from the source project if its a Move operation
						var folder = sourceProject.Files.FirstOrDefault (f => f.ProjectVirtualPath == virtualPath);
						if (folder != null)
							filesToRemove.Add (folder);
					} else {
						filesToRemove = new List<ProjectFile> ();
						var pf = sourceProject.Files.GetFileWithVirtualPath (sourceProject.GetRelativeChildPath (sourcePath));
						if (pf != null)
							filesToRemove.Add (pf);
					}
				}
				//get all the non-project files and create fake ProjectFiles
				if (!copyOnlyProjectFiles || sourceProject == null) {
					var col = new List<ProjectFile> ();
					GetAllFilesRecursive (sourcePath, col);
					if (sourceProject != null) {
						var names = new HashSet<string> (filesToRemove.Select (f => sourceProject.BaseDirectory.Combine (f.ProjectVirtualPath).ToString ()));
						foreach (var f in col)
							if (names.Add (f.Name))
							    filesToRemove.Add (f);
					} else {
						filesToRemove = col;
					}
				}
			} catch (Exception ex) {
				monitor.ReportError (GettextCatalog.GetString ("Could not get any file from '{0}'.", sourcePath), ex);
				return;
			}
			
			// Strip out all the directories to leave us with just the files.
			filesToMove = filesToRemove.Where (f => f.Subtype != Subtype.Directory).ToList ();
			
			// If copying a single file, bring any grouped children along
			ProjectFile sourceParent = null;
			if (filesToMove.Count == 1 && sourceProject != null) {
				var pf = filesToMove[0];
				if (pf != null && pf.HasChildren) {
					foreach (ProjectFile child in pf.DependentChildren) {
						filesToRemove.Add (child);
						filesToMove.Add (child);
					}
				}
				sourceParent = pf;
			}
			
			// Ensure that the destination folder is created, even if no files
			// are copied
			
			try {
				if (sourceIsFolder && !Directory.Exists (targetPath) && !movingFolder)
					FileService.CreateDirectory (targetPath);
			} catch (Exception ex) {
				monitor.ReportError (GettextCatalog.GetString ("Could not create directory '{0}'.", targetPath), ex);
				return;
			}

			// Transfer files
			// If moving a folder, do it all at once
			
			if (movingFolder) {
				try {
					FileService.MoveDirectory (sourcePath, targetPath);
				} catch (Exception ex) {
					monitor.ReportError (GettextCatalog.GetString ("Directory '{0}' could not be moved.", sourcePath), ex);
					return;
				}
			}

			if (removeFromSource)
				monitor.BeginTask (GettextCatalog.GetString ("Moving files..."), filesToMove.Count);
			else
				monitor.BeginTask (GettextCatalog.GetString ("Copying files..."), filesToMove.Count);
			
			ProjectFile targetParent = null;
			foreach (ProjectFile file in filesToMove) {
				bool fileIsLink = file.Project != null && file.IsLink;
				
				var sourceFile = fileIsLink
					? file.Project.BaseDirectory.Combine (file.ProjectVirtualPath)
					: file.FilePath;
				
				FilePath newFile;
				if (sourceIsFolder)
					newFile = targetPath.Combine (sourceFile.ToRelative (sourcePath));
				else if (sourceFile == sourcePath)
					newFile = targetPath;
				else if (sourceFile.ParentDirectory != targetPath.ParentDirectory)
					newFile = targetPath.ParentDirectory.Combine (sourceFile.ToRelative (sourcePath.ParentDirectory));
				else
					newFile = GetTargetCopyName (sourceFile, false);
				
				if (!movingFolder && !fileIsLink) {
					try {
						FilePath fileDir = newFile.ParentDirectory;
						if (!Directory.Exists (fileDir) && !file.IsLink)
							FileService.CreateDirectory (fileDir);
						if (removeFromSource) {
							// File.Move() does not have an overwrite argument and will fail if the destFile path exists, however, the user
							// has already chosen to overwrite the destination file.
							if (File.Exists (newFile))
								File.Delete (newFile);

							FileService.MoveFile (sourceFile, newFile);
						} else
							FileService.CopyFile (sourceFile, newFile);
					} catch (Exception ex) {
						if (removeFromSource)
							monitor.ReportError (GettextCatalog.GetString ("File '{0}' could not be moved.", sourceFile), ex);
						else
							monitor.ReportError (GettextCatalog.GetString ("File '{0}' could not be copied.", sourceFile), ex);
						monitor.Step (1);
						continue;
					}
				}
				
				if (fileIsLink) {
					if (sourceProject != null) {
						var linkFile = (ProjectFile)file.Clone ();
						if (movingFolder) {
							var abs = linkFile.Link.ToAbsolute (sourceProject.BaseDirectory);
							var relSrc = abs.ToRelative (sourcePath);
							var absTarg = relSrc.ToAbsolute (targetPath);
							linkFile.Link = absTarg.ToRelative (targetProject.BaseDirectory);
						} else {
							linkFile.Link = newFile.ToRelative (targetProject.BaseDirectory);
						}
						targetProject.Files.Add (linkFile);
					}
				} else if (targetProject.Files.GetFile (newFile) == null) {
					ProjectFile projectFile = (ProjectFile) file.Clone ();
					projectFile.Name = newFile;
					targetProject.Files.Add (projectFile);
					if (targetParent == null) {
						if (file == sourceParent)
							targetParent = projectFile;
					} else if (sourceParent != null) {
						if (projectFile.DependsOn == sourceParent.Name)
							projectFile.DependsOn = targetParent.Name;
					}
				}

				monitor.Step (1);
			}
			
			if (removeFromSource && sourceProject != null) {
				// Remove all files and directories under 'sourcePath'
				foreach (var v in filesToRemove)
					sourceProject.Files.Remove (v);
			}

			// Moving or copying an empty folder. A new folder object has to be added to the project.
			if (sourceIsFolder && !targetProject.Files.GetFilesInVirtualPath (targetPath).Any ()) {
				var folderFile = new ProjectFile (targetPath) { Subtype = Subtype.Directory };
				targetProject.Files.Add (folderFile);
			}
			
			var pfolder = sourcePath.ParentDirectory;
			
			// If this was the last item in the folder, make sure we keep
			// a reference to the folder, so it is not deleted from the tree.
			if (removeFromSource && sourceProject != null && pfolder.CanonicalPath != sourceProject.BaseDirectory.CanonicalPath && pfolder.IsChildPathOf (sourceProject.BaseDirectory)) {
				pfolder = pfolder.ToRelative (sourceProject.BaseDirectory);
				if (!sourceProject.Files.GetFilesInVirtualPath (pfolder).Any () && sourceProject.Files.GetFileWithVirtualPath (pfolder) == null) {
					var folderFile = new ProjectFile (sourceProject.BaseDirectory.Combine (pfolder));
					folderFile.Subtype = Subtype.Directory;
					sourceProject.Files.Add (folderFile);
				}
			}
			
			monitor.EndTask ();
		}

		static void GetTargetCopyFileNameParts(FilePath path, out string nameWithoutExtension, out string extension)
		{
			// under normal circumstances this is what we would want, foo.cs -> foo and .cs
			// however, for cases like foo.xaml.cs, we want foo and .xaml.cs
			nameWithoutExtension = path.FileNameWithoutExtension;
			extension = path.Extension;
			var x = Path.GetFileNameWithoutExtension (nameWithoutExtension);
			while (x != nameWithoutExtension) {
				extension = Path.GetExtension (nameWithoutExtension) + extension;
				nameWithoutExtension = x;
			}
		}

		internal static FilePath GetTargetCopyName (FilePath path, bool isFolder)
		{
			GetTargetCopyFileNameParts (path, out string nameWithoutExtension, out string extension);

			int n=1;
			// First of all try to find an existing copy tag
			string fn = nameWithoutExtension;
			for (int i=1; i<100; i++) {
				string copyTag = GetCopyTag (i); 
				if (fn.EndsWith (copyTag)) {
					string newfn = fn.Substring (0, fn.Length - copyTag.Length);
					if (newfn.Trim ().Length > 0) {
						n = i + 1;
						path = path.ParentDirectory.Combine (newfn + path.Extension);
						break;
					}
				}
			}
			FilePath basePath = path;
			while ((!isFolder && File.Exists (path)) || (isFolder && Directory.Exists (path))) {
				string copyTag = GetCopyTag (n);
				path = basePath.ParentDirectory.Combine (nameWithoutExtension + copyTag + extension);
				n++;
			}
			return path;
		}
		
		static string GetCopyTag (int n)
		{
			string sc;
			switch (n) {
				case 1: sc = GettextCatalog.GetString ("copy"); break;
				case 2: sc = GettextCatalog.GetString ("another copy"); break;
				case 3: sc = GettextCatalog.GetString ("3rd copy"); break;
				case 4: sc = GettextCatalog.GetString ("4th copy"); break;
				case 5: sc = GettextCatalog.GetString ("5th copy"); break;
				case 6: sc = GettextCatalog.GetString ("6th copy"); break;
				case 7: sc = GettextCatalog.GetString ("7th copy"); break;
				case 8: sc = GettextCatalog.GetString ("8th copy"); break;
				case 9: sc = GettextCatalog.GetString ("9th copy"); break;
				default: sc = GettextCatalog.GetString ("copy {0}"); break;
			}
			return " (" + string.Format (sc, n) + ")";
		}
		
		static void GetAllFilesRecursive (string path, List<ProjectFile> files)
		{
			if (File.Exists (path)) {
				files.Add (new ProjectFile (path));
				return;
			}
			
			if (Directory.Exists (path)) {
				foreach (string file in Directory.GetFiles (path))
					files.Add (new ProjectFile (file));
				
				foreach (string dir in Directory.GetDirectories (path))
					GetAllFilesRecursive (dir, files);
			}
		}
		
		static bool ContainsOnlyProjectFiles (string path, Project project)
		{
			if (Directory.EnumerateFiles (path).Any (f => project.Files.GetFile (f) == null))
				return false;
			foreach (string dir in Directory.EnumerateDirectories (path))
				if (!ContainsOnlyProjectFiles (dir, project)) return false;
			return true;
		}

		void OnBeforeStartProject()
		{
			if (BeforeStartProject != null) {
				BeforeStartProject(this, null);
			}
		}

		void OnEndBuild (ProgressMonitor monitor, bool success, BuildResult result = null, SolutionFolderItem item = null)
		{
			if (EndBuild == null)
				return;
					
			var args = new BuildEventArgs (monitor, success) {
				SolutionItem = item
			};
			if (result != null) {
				args.WarningCount = result.WarningCount;
				args.ErrorCount = result.ErrorCount;
				args.BuildCount = result.BuildCount;
				args.FailedBuildCount = result.FailedBuildCount;
			}
			EndBuild (this, args);
		}
		
		void OnStartClean (ProgressMonitor monitor, ITimeTracker tt)
		{
			tt.Trace ("Start clean event");
			IdeServices.TaskService.Errors.ClearByOwner (this);
			if (StartClean != null) {
				StartClean (this, new CleanEventArgs (monitor));
			}
		}
		
		void OnEndClean (ProgressMonitor monitor, ITimeTracker tt)
		{
			tt.Trace ("End clean event");
			if (EndClean != null) {
				EndClean (this, new CleanEventArgs (monitor));
			}
		}

		void IdeAppWorkspaceItemUnloading (object sender, ItemUnloadingEventArgs args)
		{
			if (IsBuilding (args.Item))
				CurrentBuildOperation.Cancel ();
			if (IsRunning (args.Item)) {
				if (MessageService.Confirm (GettextCatalog.GetString (
						"The project '{0}' is currently running and will have to be stopped. Do you want to continue closing it?",
						args.Item.Name),
						new AlertButton (GettextCatalog.GetString ("Close Project")))) {
					CurrentRunOperation.Cancel ();
				} else
					args.Cancel = true;
			}
		}
		
		void OnWorkspaceItemUnloaded (object s, WorkspaceItemEventArgs args)
		{
			if (ContainsTarget (args.Item, workspace.CurrentSelectedSolutionItem))
				CurrentSelectedSolutionItem = null;
			if (ContainsTarget (args.Item, CurrentSelectedWorkspaceItem))
				CurrentSelectedWorkspaceItem = null;
			if ((CurrentSelectedItem is WorkspaceObject) && ContainsTarget (args.Item, ((WorkspaceObject)CurrentSelectedItem)))
				CurrentSelectedItem = null;
		}
		
		public event BuildEventHandler StartBuild;
		public event BuildEventHandler EndBuild;
		public event EventHandler BeforeStartProject;
		public event CleanEventHandler StartClean;
		public event CleanEventHandler EndClean;

		public event EventHandler<SolutionEventArgs> CurrentSelectedSolutionChanged {
			add {
				workspace.CurrentSelectedSolutionChanged += value;
			}
			remove {
				workspace.CurrentSelectedSolutionChanged -= value;
			}
		}

		public event ProjectEventHandler CurrentProjectChanged {
			add {
				workspace.CurrentProjectChanged += value;
			}

			remove {
				workspace.CurrentProjectChanged -= value;
			}
		}

		public event EventHandler<ProjectCreatedEventArgs> ProjectCreated;
		
		// Fired just before an entry is added to a combine
		public event AddEntryEventHandler AddingEntryToCombine;

		public event EventHandler CurrentRunOperationChanged;
		public event EventHandler<EditReferencesEventArgs> BeforeEditReferences;
		protected virtual void OnCurrentRunOperationChanged (EventArgs e)
		{
			var handler = CurrentRunOperationChanged;
			if (handler != null)
				handler (this, e);
		}
	}
	
	class ParseProgressMonitorFactory: IProgressMonitorFactory
	{
		public ProgressMonitor CreateProgressMonitor ()
		{
			return new BackgroundProgressMonitor (GettextCatalog.GetString ("Code completion database generation"), "md-parser");
		}
	}

	public interface ITextFileProvider
	{
		ITextDocument GetEditableTextFile (FilePath filePath);
	}

	class MultipleAsyncOperation : AsyncOperation
	{
		public static MultipleAsyncOperation CompleteMultipleOperation = new MultipleAsyncOperation (true);

		List<AsyncOperation> Operations = new List<AsyncOperation> ();
		TaskCompletionSource<int> TaskCompletionSource = new TaskCompletionSource<int> ();

		public MultipleAsyncOperation ()
		{
			Task = TaskCompletionSource.Task;
			CancellationTokenSource.Token.Register (MultiCancel);
		}

		MultipleAsyncOperation (bool completed)
		{
			if (completed)
				TaskCompletionSource.SetResult (0);
		}

		public void AddOperation (AsyncOperation op)
		{
			Operations.Add (op);
			op.Task.ContinueWith (t => CheckForCompletion (t));
		}

		void CheckForCompletion (Task obj)
		{
			if (Operations.All (op => op.IsCompleted)) {
				TaskCompletionSource.SetResult (0);
			}
		}

		void MultiCancel ()
		{
			foreach (var op in Operations) {
				op.Cancel ();
			}
		}
	}

	[Obsolete("Use VS Editor APIs")]
	public class TextFileProvider : ITextFileProvider
	{
		static TextFileProvider instance = new TextFileProvider ();
		public static TextFileProvider Instance {
			get {
				return instance;
			}
		}
		
		TextFileProvider ()
		{
		}

		public ITextDocument GetEditableTextFile (FilePath filePath)
		{
			foreach (var doc in IdeServices.DocumentManager.Documents) {
				if (doc.FileName == filePath) {
					var ef = doc.Editor;
					if (ef != null) return ef;
				}
			}

			return TextEditorFactory.CreateNewDocument (StringTextSource.ReadFrom (filePath), filePath);
		}

		/// <summary>
		/// Performs an edit operation on a text file regardless of it's open in the IDE or not.
		/// </summary>
		/// <returns><c>true</c>, if file operation was saved, <c>false</c> otherwise.</returns>
		/// <param name="filePath">File path.</param>
		/// <param name="operation">The operation.</param>
		public bool EditFile (FilePath filePath, Action<ITextDocument> operation)
		{
			if (operation == null)
				throw new ArgumentNullException ("operation");
			bool isOpen;
			var data = GetTextEditorData (filePath, out isOpen);
			operation (data);
			if (!isOpen) {
				try {
					data.Save ();
				} catch (Exception e) {
					LoggingService.LogError ("Error while saving changes to : " + filePath, e);
					return false;
				}
			}
			return true;
		}

		public ITextDocument GetTextEditorData (FilePath filePath)
		{
			bool isOpen;
			return GetTextEditorData (filePath, out isOpen);
		}

		public IReadonlyTextDocument GetReadOnlyTextEditorData (FilePath filePath)
		{
			if (filePath.IsNullOrEmpty)
				throw new ArgumentNullException ("filePath");
			foreach (var doc in IdeServices.DocumentManager.Documents) {
				if (IsSearchedDocument (doc, filePath)) {
					return doc.Editor;
				}
			}
			var data = TextEditorFactory.CreateNewReadonlyDocument (StringTextSource.ReadFrom (filePath), filePath);
			return data;
		}

		public ITextDocument GetTextEditorData (FilePath filePath, out bool isOpen)
		{
			foreach (var doc in IdeServices.DocumentManager.Documents) {
				if (IsSearchedDocument (doc, filePath)) {
					isOpen = true;
					return doc.Editor;
				}
			}

			var data = TextEditorFactory.CreateNewDocument (filePath, IdeServices.DesktopService.GetMimeTypeForUri(filePath));

			isOpen = false;
			return data;
		}

		static bool IsSearchedDocument (Document doc, FilePath filePath)
		{
			return doc.IsFile && doc.Editor != null && doc.FileName != null && FilePath.PathComparer.Compare (Path.GetFullPath (doc.FileName), filePath) == 0;
		}
	}
}
