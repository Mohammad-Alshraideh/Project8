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
    public class DoctorsController : Controller
    {
        private Project8Entities db = new Project8Entities();

        // GET: Doctors
        public ActionResult Index()
        {
            var doctors = db.Doctors.Include(d => d.AspNetUser);
            return View(doctors.ToList());
        }

        // GET: Doctors/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Doctor doctor = db.Doctors.Find(id);
            if (doctor == null)
            {
                return HttpNotFound();
            }
            return View(doctor);
        }

        // GET: Doctors/Create
        public ActionResult Create()
        {
            ViewBag.User_ID = new SelectList(db.AspNetUsers, "Id", "Email");
            return View();
        }

        // POST: Doctors/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "Doctor_Id,Doctor_Name,Doctor_Image,Doctor_Phone,Doctor_Email")] Doctor doctor,HttpPostedFileBase Doctor_Image)
        {
            if (ModelState.IsValid)
            {
                Guid guid1 = Guid.NewGuid();

                doctor.Doctor_Image = guid1 + "-" + Doctor_Image.FileName;
                string doctorimg = guid1 + "-" + Doctor_Image.FileName;
                Doctor_Image.SaveAs(Server.MapPath("../Images/" + doctorimg));
                db.Doctors.Add(doctor);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            ViewBag.User_ID = new SelectList(db.AspNetUsers, "Id", "Email", doctor.User_ID);
            return View(doctor);
        }

        // GET: Doctors/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Doctor doctor = db.Doctors.Find(id);
            if (doctor == null)
            {
                return HttpNotFound();
            }
            ViewBag.User_ID = new SelectList(db.AspNetUsers, "Id", "Email", doctor.User_ID);
            return View(doctor);
        }

        // POST: Doctors/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int? id,[Bind(Include = "Doctor_Id,Doctor_Name,Doctor_Image,Doctor_Phone,Doctor_Email,User_ID")] Doctor doctor, HttpPostedFileBase Doctor_Image)
        {

            if (ModelState.IsValid)
            {
                var existingModel = db.Doctors.AsNoTracking().FirstOrDefault(x => x.Doctor_Id == id);

                if (Doctor_Image != null)
                {
                    Guid guid1 = Guid.NewGuid();

                    doctor.Doctor_Image = guid1 + "-" + Doctor_Image.FileName;
                    string collegeImage = guid1 + "-" + Doctor_Image.FileName;
                    Doctor_Image.SaveAs(Server.MapPath("../../Images/" + collegeImage));
                }
                else
                {
                    doctor.Doctor_Image = existingModel.Doctor_Image;
                }
                db.Entry(doctor).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            ViewBag.User_ID = new SelectList(db.AspNetUsers, "Id", "Email", doctor.User_ID);
            return View(doctor);
        }

        // GET: Doctors/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Doctor doctor = db.Doctors.Find(id);
            if (doctor == null)
            {
                return HttpNotFound();
            }
            return View(doctor);
        }

        // POST: Doctors/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            Doctor doctor = db.Doctors.Find(id);
            db.Doctors.Remove(doctor);
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
