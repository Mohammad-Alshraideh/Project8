using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;

namespace Project8.Controllers
{
    public class dashboard_layoutController : Controller
    {
        // GET: dashboard_layout
        public ActionResult Index()
        {
            return View();
        }


    }
}