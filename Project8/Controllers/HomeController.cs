using Project8.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Project8.Controllers
{
    public class HomeController : Controller
    {
        Project8Entities db = new Project8Entities();
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
        public ActionResult Collages()
        {
            var collages = db.Colleges.ToList();
            return View(collages);
        }
        public ActionResult Majors(int? id)
        {
            if (id == null)
            {
                return RedirectToAction("Collages");
            }
            var majors = db.Majors.Where(x => x.College_Id == id).ToList();
            return View(majors);
        }

        public ActionResult singleMajor(int? id)
        {
            if (id == null)
            {
                return RedirectToAction("Majors");
            }
            var majors = db.Majors.Where(x => x.Major_Id == id).ToList();
            return View(majors);
        }
    }
}