using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace MonoDevelop.ConnectedServices
{
	/// <summary>
	/// Represents a set of dependencies that are added to the project.
	/// </summary>
	public sealed class GroupedDependency : ConnectedServiceDependency
	{
		readonly GroupedDependencyKind kind;
		readonly ConnectedServiceDependency [] dependencies;

		public GroupedDependency (IConnectedService service, string displayName, GroupedDependencyKind kind, ConnectedServiceDependency[] dependencies) : base (service, ConnectedServices.CodeDependencyCategory, displayName)
		{
			this.kind = kind;
			this.dependencies = dependencies;
		}

		/// <summary>
		/// Adds the dependency to the project and returns true if the dependency was added to the project
		/// </summary>
		protected override async Task<bool> OnAddToProject (bool licensesAccepted, CancellationToken token)
		{
			if (this.dependencies.Length == 0) {
				return true;
			}

			switch (this.kind) {
				case GroupedDependencyKind.All:
				bool added = true;
				foreach (var dependency in this.dependencies) {
					added &= await dependency.AddToProject (licensesAccepted, token).ConfigureAwait (false);
				}
				return added;

				case GroupedDependencyKind.Any:
				foreach (var dependency in this.dependencies) {
					if (await dependency.AddToProject (licensesAccepted, token).ConfigureAwait (false)) {
						return true;
					}
				}

				return false;

				default:
				throw new NotSupportedException (string.Format ("Unsupported GroupedDependencyKind {0}", this.kind));
			}
		}

		/// <summary>
		/// Gets a value indicating whether this <see cref="T:MonoDevelop.ConnectedServices.IConnectedServiceDependency"/> is added to the project or not.
		/// </summary>
		public override bool IsAdded {
			get {

				switch (this.kind) {
				case GroupedDependencyKind.All:
					return this.dependencies.All (x => x.IsAdded);

				case GroupedDependencyKind.Any:
					return this.dependencies.Any (x => x.IsAdded);

				default:
					throw new NotSupportedException (string.Format ("Unsupported GroupedDependencyKind {0}", this.kind));
				}
			}
		}

		/// <summary>
		/// Removes the dependency from the project
		/// </summary>
		protected override async Task<bool> OnRemoveFromProject (CancellationToken token)
		{
			if (this.dependencies.Length == 0) {
				return true;
			}

			var result = true;
			foreach (var dependency in this.dependencies.Reverse ()) {
				if (dependency.IsAdded) {
					if (!await dependency.RemoveFromProject (token).ConfigureAwait (false)) {
						result = false;
					}
				}
			}

			return result;
		}
	}
}