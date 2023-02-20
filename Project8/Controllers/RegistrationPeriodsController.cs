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
    public class RegistrationPeriodsController : Controller
    {
        private Project8Entities db = new Project8Entities();

        // GET: RegistrationPeriods
        public ActionResult Index()
        {
            var registrationPeriods = db.RegistrationPeriods.Include(r => r.semester);
            return View(registrationPeriods.ToList());
        }

        // GET: RegistrationPeriods/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            RegistrationPeriod registrationPeriod = db.RegistrationPeriods.Find(id);
            if (registrationPeriod == null)
            {
                return HttpNotFound();
            }
            return View(registrationPeriod);
        }

        // GET: RegistrationPeriods/Create
        public ActionResult Create()
        {
            ViewBag.semester_id = new SelectList(db.semesters, "id", "name");
            return View();
        }

        // POST: RegistrationPeriods/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "id,semester_id,start_date,end_date")] RegistrationPeriod registrationPeriod)
        {
            if (ModelState.IsValid)
            {
                db.RegistrationPeriods.Add(registrationPeriod);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            ViewBag.semester_id = new SelectList(db.semesters, "id", "name", registrationPeriod.semester_id);
            return View(registrationPeriod);
        }

        // GET: RegistrationPeriods/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            RegistrationPeriod registrationPeriod = db.RegistrationPeriods.Find(id);
            if (registrationPeriod == null)
            {
                return HttpNotFound();
            }
            ViewBag.semester_id = new SelectList(db.semesters, "id", "name", registrationPeriod.semester_id);
            return View(registrationPeriod);
        }

        // POST: RegistrationPeriods/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "id,semester_id,start_date,end_date")] RegistrationPeriod registrationPeriod)
        {
            if (ModelState.IsValid)
            {
                db.Entry(registrationPeriod).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            ViewBag.semester_id = new SelectList(db.semesters, "id", "name", registrationPeriod.semester_id);
            return View(registrationPeriod);
        }

        // GET: RegistrationPeriods/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            RegistrationPeriod registrationPeriod = db.RegistrationPeriods.Find(id);
            if (registrationPeriod == null)
            {
                return HttpNotFound();
            }
            return View(registrationPeriod);
        }

        // POST: RegistrationPeriods/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            RegistrationPeriod registrationPeriod = db.RegistrationPeriods.Find(id);
            db.RegistrationPeriods.Remove(registrationPeriod);
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
