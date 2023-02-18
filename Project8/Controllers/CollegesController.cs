using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Web;
using System.Web.Mvc;
using Project8.Models;

namespace Project8.Controllers
{
    public class CollegesController : Controller
    {
        private Project8Entities db = new Project8Entities();

        // GET: Colleges
        public ActionResult Index()
        {
            return View(db.Colleges.ToList());
        }

        // GET: Colleges/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            College college = db.Colleges.Find(id);
            if (college == null)
            {
                return HttpNotFound();
            }
            return View(college);
        }

        // GET: Colleges/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Colleges/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "College_Id,College_Name,College_Description,College_Image")] College college,HttpPostedFileBase College_Image)
        {
            if (ModelState.IsValid)
            {
                Guid guid1 = Guid.NewGuid();

                college.College_Image = guid1 + "-" + College_Image.FileName;
                string collegeImage = guid1 + "-" + College_Image.FileName;
                College_Image.SaveAs(Server.MapPath("../Images/" + collegeImage)); 
                db.Colleges.Add(college);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            return View(college);
        }

        // GET: Colleges/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            College college = db.Colleges.Find(id);
            if (college == null)
            {
                return HttpNotFound();
            }
            return View(college);
        }

        // POST: Colleges/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int? id,[Bind(Include = "College_Id,College_Name,College_Description,College_Image")] College college, HttpPostedFileBase College_Image)
        {
            if (ModelState.IsValid)
            {
                var existingModel = db.Colleges.AsNoTracking().FirstOrDefault(x => x.College_Id == id);

                if (College_Image != null)
                {
                    Guid guid1 = Guid.NewGuid();

                    college.College_Image = guid1 + "-" + College_Image.FileName;
                    string collegeImage = guid1 + "-" + College_Image.FileName;
                    College_Image.SaveAs(Server.MapPath("../../Images/" + collegeImage));
                }
                else
                {
                    college.College_Image = existingModel.College_Image;
                }
              
                db.Entry(college).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            return View(college);
        }

        // GET: Colleges/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            College college = db.Colleges.Find(id);
            if (college == null)
            {
                return HttpNotFound();
            }
            return View(college);
        }

        // POST: Colleges/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            College college = db.Colleges.Find(id);
            db.Colleges.Remove(college);
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
