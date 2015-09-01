using System.Web.Http;

namespace TAC.WebApiAuthentication.Controllers
{
    public class ValuesController : ApiController
    {

        [Authorize(Roles = "normal")]
        public string Get()
        {
            return User.Identity.Name;
        }

        [Authorize(Roles = "admin")]
        public void Put()
        {

        }
    }
}