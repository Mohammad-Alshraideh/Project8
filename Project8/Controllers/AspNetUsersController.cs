using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;
using System.Web.Services.Description;
using Project8.Models;

namespace Project8.Controllers
{
    public class AspNetUsersController : Controller
    {
        private Project8Entities db = new Project8Entities();

        // GET: AspNetUsers
        public ActionResult Index()
        {     

            var aspNetUsers = db.AspNetUsers.Include(a => a.Major);
            return View(aspNetUsers.ToList());
        }
        [HttpPost]
        public ActionResult Index(string search5)
        {
            if (search5 != null)
            {
                var abumahmood = db.AspNetUsers.Where(x => x.Email.Contains(search5)).ToList();

                return View(abumahmood);
            }

            var aspNetUsers = db.AspNetUsers.Include(a => a.Major);
            return View(aspNetUsers.ToList());
        }

        // GET: AspNetUsers/Details/5
        public ActionResult Details(string id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            AspNetUser aspNetUser = db.AspNetUsers.Find(id);
            if (aspNetUser == null)
            {
                return HttpNotFound();
            }
            return View(aspNetUser);
        }

        // GET: AspNetUsers/Create
        public ActionResult Create()
        {
            ViewBag.Major_Id = new SelectList(db.Majors, "Major_Id", "Major_Name");
            return View();
        }

        // POST: AspNetUsers/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "Id,Email,EmailConfirmed,PasswordHash,SecurityStamp,PhoneNumber,PhoneNumberConfirmed,TwoFactorEnabled,LockoutEndDateUtc,LockoutEnabled,AccessFailedCount,UserName,user_image,Id_Image,National_Number,HighSchool_Image,HighSchool_Avg,First_Name,Last_Name,Major_Id,IsAccepted,Balance")] AspNetUser aspNetUser)
        {
            if (ModelState.IsValid)
            {
                db.AspNetUsers.Add(aspNetUser);
                db.SaveChanges();
                return RedirectToAction("Index");
            }

            ViewBag.Major_Id = new SelectList(db.Majors, "Major_Id", "Major_Name", aspNetUser.Major_Id);
            return View(aspNetUser);
        }

        // GET: AspNetUsers/Edit/5
        public ActionResult Edit(string id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            AspNetUser aspNetUser = db.AspNetUsers.Find(id);
            if (aspNetUser == null)
            {
                return HttpNotFound();
            }
            ViewBag.Major_Id = new SelectList(db.Majors, "Major_Id", "Major_Name", aspNetUser.Major_Id);
            return View(aspNetUser);
        }

        // POST: AspNetUsers/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "Id,Email,EmailConfirmed,PasswordHash,SecurityStamp,PhoneNumber,PhoneNumberConfirmed,TwoFactorEnabled,LockoutEndDateUtc,LockoutEnabled,AccessFailedCount,UserName,user_image,Id_Image,National_Number,HighSchool_Image,HighSchool_Avg,First_Name,Last_Name,Major_Id,IsAccepted,Balance")] AspNetUser aspNetUser)
        {
            if (ModelState.IsValid)
            {
                db.Entry(aspNetUser).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("Index");
            }
            ViewBag.Major_Id = new SelectList(db.Majors, "Major_Id", "Major_Name", aspNetUser.Major_Id);
            return View(aspNetUser);
        }
        public ActionResult Accept(string id) {
            var student = db.AspNetUsers.Find(id);
            student.IsAccepted = true;
            var role = db.AspNetUserRoles.Where(x => x.UserId == id).FirstOrDefault();
            db.AspNetUserRoles.Remove(role);
            var role1 = new AspNetUserRole();
            role1.UserId = id;
            role1.RoleId = "2";
            db.AspNetUserRoles.Add(role1);
            db.SaveChanges();
            MailMessage mail = new MailMessage();
            mail.To.Add(student.Email);
            mail.From = new MailAddress("jaberfahd2233@gmail.com");
            mail.Subject = "Accept";

            mail.Body = "Wellcom";
            mail.IsBodyHtml = true;

            SmtpClient smtp = new SmtpClient();
            smtp.Port = 587;
            smtp.EnableSsl = true;
            smtp.UseDefaultCredentials = false;
            smtp.Host = "smtp.gmail.com";
            smtp.Credentials = new System.Net.NetworkCredential("jaberfahd2233", "obsrmfoexbukaspu");
            smtp.Send(mail);
            return View("Index",db.AspNetUsers.ToList());
        }
        public ActionResult Reject(string id)
        {
            var student = db.AspNetUsers.Find(id);
            student.IsAccepted = false;
            db.SaveChanges();
            MailMessage mail = new MailMessage();
            mail.To.Add(student.Email);
            mail.From = new MailAddress("jaberfahd2233@gmail.com");
            mail.Subject = "Reject";

            mail.Body = "Wellcom";
            mail.IsBodyHtml = true;

            SmtpClient smtp = new SmtpClient();
            smtp.Port = 587;
            smtp.EnableSsl = true;
            smtp.UseDefaultCredentials = false;
            smtp.Host = "smtp.gmail.com";
            smtp.Credentials = new System.Net.NetworkCredential("jaberfahd2233", "obsrmfoexbukaspu");
            smtp.Send(mail);
            return View("Index", db.AspNetUsers.ToList());
        }
        // GET: AspNetUsers/Delete/5
        public ActionResult Delete(string id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            AspNetUser aspNetUser = db.AspNetUsers.Find(id);
            if (aspNetUser == null)
            {
                return HttpNotFound();
            }
            return View(aspNetUser);
        }

        // POST: AspNetUsers/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(string id)
        {
            AspNetUser aspNetUser = db.AspNetUsers.Find(id);
            db.AspNetUsers.Remove(aspNetUser);
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
        //public ActionResult Search(string search)
        //{
        //    var abumahmood = db.AspNetUsers.Where(x => x.Email.Contains(search)).ToList();
        //    return View("Index",abumahmood);
        //}
    }
}
