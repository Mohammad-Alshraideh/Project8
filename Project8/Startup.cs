using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Project8.Startup))]
namespace Project8
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
