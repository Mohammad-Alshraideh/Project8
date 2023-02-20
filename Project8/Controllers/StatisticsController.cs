using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;
using Project8.Models;
namespace Project8.Controllers
{
    [Authorize(Roles = "Admin")]

    public class StatisticsController : Controller
    {
        // GET: Statistics
        Project8Entities db=new Project8Entities();
        public ActionResult Index()
        {
            ViewBag.Accepted = db.AspNetUsers.Count(x=>x.IsAccepted==true);
            ViewBag.Rejected = db.AspNetUsers.Count(x => x.IsAccepted == false);
            ViewBag.non = db.AspNetUsers.Count(x => x.IsAccepted == null);

            ViewBag.All = db.AspNetUsers.Count(x => x.IsAccepted == true || x.IsAccepted == false);
            ViewBag.MyMoney = db.Transactions.Count(x => x.User_Action == false);
            ViewBag.Money = db.Transactions.Where(x=>x.User_Action==false).Sum(x => x.Amount);
            return View();
        }
        public ActionResult CreatePie()
        {

            int Accepted=db.AspNetUsers.Count(x => x.IsAccepted == true);
            int rejected = db.AspNetUsers.Count(x => x.IsAccepted == false);
            int Pending = db.AspNetUsers.Count(x => x.IsAccepted == null);

            var chart = new Chart(width: 500, height: 400)
            .AddSeries(chartType: "pie",
        xValue: new[] { "Accepted", "Rejected", "Pending" },
        yValues: new[] {  Accepted,rejected,Pending })
                            .GetBytes("png");
            return File(chart, "image/bytes");
        }
    }

}