using System;
using System.Data.Entity;
using System.Dynamic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Net.Mime;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Project8.Controllers;
using Project8.Models;


 


namespace Project8.Controllers
{
    [Authorize]

    public class ManageController : Controller
    {
        Project8Entities db = new Project8Entities();
        private ApplicationSignInManager _signInManager;
        private ApplicationUserManager _userManager;

        public ManageController()
        {
        }
   
        public ManageController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            UserManager = userManager;
            SignInManager = signInManager;
        }

        public ApplicationSignInManager SignInManager
        {
            get
            {
                return _signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set 
            { 
                _signInManager = value; 
            }
        }

        public ApplicationUserManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
            private set
            {
                _userManager = value;
            }
        }

        //
        // GET: /Manage/Index
        public async Task<ActionResult> Index(ManageMessageId? message)
        {
           
            ViewBag.StatusMessage =
                message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
                : message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
                : message == ManageMessageId.SetTwoFactorSuccess ? "Your two-factor authentication provider has been set."
                : message == ManageMessageId.Error ? "An error has occurred."
                : message == ManageMessageId.AddPhoneSuccess ? "Your phone number was added."
                : message == ManageMessageId.RemovePhoneSuccess ? "Your phone number was removed."
                : "";
            ViewBag.sender = "MyInformation";
            var userId = User.Identity.GetUserId();
            var UserInfo = db.AspNetUsers.Where(x => x.Id == userId);
            var model = new IndexViewModel
            {
                HasPassword = HasPassword(),
                PhoneNumber = await UserManager.GetPhoneNumberAsync(userId),
                TwoFactor = await UserManager.GetTwoFactorEnabledAsync(userId),
                Logins = await UserManager.GetLoginsAsync(userId),
                BrowserRemembered = await AuthenticationManager.TwoFactorBrowserRememberedAsync(userId),
      

            };
            ViewBag.CurrentBalance = db.AspNetUsers.Find(User.Identity.GetUserId()).Balance;
            return View(UserInfo.FirstOrDefault());
        }

        //
        // POST: /Manage/RemoveLogin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemoveLogin(string loginProvider, string providerKey)
        {
            ManageMessageId? message;
            var result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(), new UserLoginInfo(loginProvider, providerKey));
            if (result.Succeeded)
            {
                var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                if (user != null)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                }
                message = ManageMessageId.RemoveLoginSuccess;
            }
            else
            {
                message = ManageMessageId.Error;
            }
            return RedirectToAction("ManageLogins", new { Message = message });
        }

        //
        // GET: /Manage/AddPhoneNumber
        public ActionResult AddPhoneNumber()
        {
            return View();
        }

        //
        // POST: /Manage/AddPhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> AddPhoneNumber(AddPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            // Generate the token and send it
            var code = await UserManager.GenerateChangePhoneNumberTokenAsync(User.Identity.GetUserId(), model.Number);
            if (UserManager.SmsService != null)
            {
                var message = new IdentityMessage
                {
                    Destination = model.Number,
                    Body = "Your security code is: " + code
                };
                await UserManager.SmsService.SendAsync(message);
            }
            return RedirectToAction("VerifyPhoneNumber", new { PhoneNumber = model.Number });
        }

        //
        // POST: /Manage/EnableTwoFactorAuthentication
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> EnableTwoFactorAuthentication()
        {
            await UserManager.SetTwoFactorEnabledAsync(User.Identity.GetUserId(), true);
            var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            if (user != null)
            {
                await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
            }
            return RedirectToAction("Index", "Manage");
        }

        //
        // POST: /Manage/DisableTwoFactorAuthentication
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> DisableTwoFactorAuthentication()
        {
            await UserManager.SetTwoFactorEnabledAsync(User.Identity.GetUserId(), false);
            var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            if (user != null)
            {
                await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
            }
            ViewBag.CurrentBalance = db.AspNetUsers.Find(User.Identity.GetUserId()).Balance;
            return RedirectToAction("Index", "Manage");
        }

        //
        // GET: /Manage/VerifyPhoneNumber
        public async Task<ActionResult> VerifyPhoneNumber(string phoneNumber)
        {
            var code = await UserManager.GenerateChangePhoneNumberTokenAsync(User.Identity.GetUserId(), phoneNumber);
            // Send an SMS through the SMS provider to verify the phone number
            return phoneNumber == null ? View("Error") : View(new VerifyPhoneNumberViewModel { PhoneNumber = phoneNumber });
        }

        //
        // POST: /Manage/VerifyPhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> VerifyPhoneNumber(VerifyPhoneNumberViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var result = await UserManager.ChangePhoneNumberAsync(User.Identity.GetUserId(), model.PhoneNumber, model.Code);
            if (result.Succeeded)
            {
                var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                if (user != null)
                {
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                }
                return RedirectToAction("Index", new { Message = ManageMessageId.AddPhoneSuccess });
            }
            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "Failed to verify phone");
            return View(model);
        }

        //
        // POST: /Manage/RemovePhoneNumber
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> RemovePhoneNumber()
        {
            var result = await UserManager.SetPhoneNumberAsync(User.Identity.GetUserId(), null);
            if (!result.Succeeded)
            {
                return RedirectToAction("Index", new { Message = ManageMessageId.Error });
            }
            var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            if (user != null)
            {
                await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
            }

            return RedirectToAction("Index", new { Message = ManageMessageId.RemovePhoneSuccess });
        }

        //
        // GET: /Manage/ChangePassword
        public ActionResult ChangePassword()
        {
            return View();
        }

        //
        // POST: /Manage/ChangePassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.PhoneNumber = db.AspNetUsers.Find(User.Identity.GetUserId()).PhoneNumber;
                ViewBag.CurrentBalance = db.AspNetUsers.Find(User.Identity.GetUserId()).Balance;
                ViewBag.Email = db.AspNetUsers.Find(User.Identity.GetUserId()).Email;
                ViewBag.sender = "ManageProfile";
                return View("index");
            }
            var result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword, model.NewPassword);
            if (result.Succeeded)
            {
                var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                if (user != null)
                {
                    ViewBag.PhoneNumber = db.AspNetUsers.Find(User.Identity.GetUserId()).PhoneNumber;
                    ViewBag.CurrentBalance = db.AspNetUsers.Find(User.Identity.GetUserId()).Balance;
                    ViewBag.Email = db.AspNetUsers.Find(User.Identity.GetUserId()).Email;
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                }
                return RedirectToAction("ManageProfile", new { Message = ManageMessageId.ChangePasswordSuccess });
            }
            ViewBag.PhoneNumber = db.AspNetUsers.Find(User.Identity.GetUserId()).PhoneNumber;
            ViewBag.CurrentBalance = db.AspNetUsers.Find(User.Identity.GetUserId()).Balance;
            ViewBag.Email = db.AspNetUsers.Find(User.Identity.GetUserId()).Email;
            AddErrors(result);
            ViewBag.sender = "ManageProfile";
            return View("index");
        }

        //
        // GET: /Manage/SetPassword
        public ActionResult SetPassword()
        {
            return View();
        }

        //
        // POST: /Manage/SetPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SetPassword(SetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);
                if (result.Succeeded)
                {
                    var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                    if (user != null)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                    }
                    return RedirectToAction("Index", new { Message = ManageMessageId.SetPasswordSuccess });
                }
                AddErrors(result);
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Manage/ManageLogins
        public async Task<ActionResult> ManageLogins(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
                : message == ManageMessageId.Error ? "An error has occurred."
                : "";
            var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            if (user == null)
            {
                return View("Error");
            }
            var userLogins = await UserManager.GetLoginsAsync(User.Identity.GetUserId());
            var otherLogins = AuthenticationManager.GetExternalAuthenticationTypes().Where(auth => userLogins.All(ul => auth.AuthenticationType != ul.LoginProvider)).ToList();
            ViewBag.ShowRemoveButton = user.PasswordHash != null || userLogins.Count > 1;
            return View(new ManageLoginsViewModel
            {
                CurrentLogins = userLogins,
                OtherLogins = otherLogins
            });
        }

        //
        // POST: /Manage/LinkLogin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LinkLogin(string provider)
        {
            // Request a redirect to the external login provider to link a login for the current user
            return new AccountController.ChallengeResult(provider, Url.Action("LinkLoginCallback", "Manage"), User.Identity.GetUserId());
        }

        //
        // GET: /Manage/LinkLoginCallback
        public async Task<ActionResult> LinkLoginCallback()
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync(XsrfKey, User.Identity.GetUserId());
            if (loginInfo == null)
            {
                return RedirectToAction("ManageLogins", new { Message = ManageMessageId.Error });
            }
            var result = await UserManager.AddLoginAsync(User.Identity.GetUserId(), loginInfo.Login);
            return result.Succeeded ? RedirectToAction("ManageLogins") : RedirectToAction("ManageLogins", new { Message = ManageMessageId.Error });
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }

            base.Dispose(disposing);
        }
        public ActionResult MyCourses()
        {
            var userId = User.Identity.GetUserId();
            //var course = db.Enrollments.Where(x => x.Student_id == userId).ToList();
            var ok = db.AspNetRoles.FirstOrDefault();
            ViewBag.sender = "MyCourses";
            ViewBag.CurrentBalance = db.AspNetUsers.Find(User.Identity.GetUserId()).Balance;
            // Request a redirect to the external login provider to link a login for the current user
            return View("index" , ok);
        }
        //get
        public ActionResult Balance()
        {
            ViewBag.PhoneNumber = db.AspNetUsers.Find(User.Identity.GetUserId()).PhoneNumber;
            ViewBag.CurrentBalance = db.AspNetUsers.Find(User.Identity.GetUserId()).Balance;
            ViewBag.Email = db.AspNetUsers.Find(User.Identity.GetUserId()).Email;
            ViewBag.sender = "Balance";
            return View("index");
        }
        public ActionResult ManageProfile()
        {
            string iddd = User.Identity.GetUserId();
   
            ViewBag.PhoneNumber = db.AspNetUsers.Find(User.Identity.GetUserId()).PhoneNumber;
            ViewBag.CurrentBalance = db.AspNetUsers.Find(User.Identity.GetUserId()).Balance;
          
            ViewBag.Email = db.AspNetUsers.Find(User.Identity.GetUserId()).Email;
            ViewBag.sender = "ManageProfile";
            return View("index") ;
        }
   
        public ActionResult Pay([Bind(Include = "Id,Email,EmailConfirmed,PasswordHash,SecurityStamp,PhoneNumber,PhoneNumberConfirmed,TwoFactorEnabled,LockoutEndDateUtc,LockoutEnabled,AccessFailedCount,UserName,user_image,Id_Image,National_Number,HighSchool_Image,HighSchool_Avg,First_Name,Last_Name,Major_Id,IsAccepted,Balance")] AspNetUser aspNetUser , string PayButton , string CardNumber , string CVC , string CardHolder)
        {
            int CurrentBalance = Convert.ToInt32(db.AspNetUsers.Find(User.Identity.GetUserId()).Balance);
            var balance = db.AspNetUsers.Find(User.Identity.GetUserId());
            Transaction trans = new Transaction();
            trans.Transaction_Date= DateTime.Now;
            trans.UserId= User.Identity.GetUserId();
            trans.Amount = Convert.ToInt32(PayButton);
            trans.User_Action = true;
            trans.CardNumber = Convert.ToInt32(CardNumber);
            trans.CVC= Convert.ToInt32(CVC);
            trans.FullName= CardHolder;
            db.Transactions.Add(trans);
            balance.Balance = Convert.ToInt32(PayButton) + CurrentBalance;
            MailMessage mail = new MailMessage();
            mail.To.Add(balance.Email);
            mail.From = new MailAddress("jaberfahd2233@gmail.com");
            mail.Subject = "Deposit";

            mail.Body = $"We Recieved your payemnt of {PayButton} ";
            mail.IsBodyHtml = true;

            SmtpClient smtp = new SmtpClient();
            smtp.Port = 587;
            smtp.EnableSsl = true;
            smtp.UseDefaultCredentials = false;
            smtp.Host = "smtp.gmail.com";
            smtp.Credentials = new System.Net.NetworkCredential("jaberfahd2233", "obsrmfoexbukaspu");
            smtp.Send(mail);
            db.SaveChanges();
            ViewBag.CurrentBalance = db.AspNetUsers.Find(User.Identity.GetUserId()).Balance;
            ViewBag.PhoneNumber = db.AspNetUsers.Find(User.Identity.GetUserId()).PhoneNumber;
            ViewBag.Email = db.AspNetUsers.Find(User.Identity.GetUserId()).Email;
            ViewBag.sender = "Balance";
            return View("index");
        }

        [HttpPost]
        public ActionResult ChangePhone([Bind(Include = "Id,Email,EmailConfirmed,PasswordHash,SecurityStamp,PhoneNumber,PhoneNumberConfirmed,TwoFactorEnabled,LockoutEndDateUtc,LockoutEnabled,AccessFailedCount,UserName,user_image,Id_Image,National_Number,HighSchool_Image,HighSchool_Avg,First_Name,Last_Name,Major_Id,IsAccepted,Balance")] AspNetUser aspNetUser , string Pnumber)
        {
            if(!string.IsNullOrEmpty(Pnumber))
            {

           
            var phon = db.AspNetUsers.Find(User.Identity.GetUserId());
            phon.PhoneNumber = Pnumber;
            ViewBag.PhoneNumber = db.AspNetUsers.Find(User.Identity.GetUserId()).PhoneNumber;
            ViewBag.CurrentBalance = db.AspNetUsers.Find(User.Identity.GetUserId()).Balance;
            db.SaveChanges();
            }
            ViewBag.PhoneNumber = db.AspNetUsers.Find(User.Identity.GetUserId()).PhoneNumber;
            ViewBag.CurrentBalance = db.AspNetUsers.Find(User.Identity.GetUserId()).Balance;
            ViewBag.Email = db.AspNetUsers.Find(User.Identity.GetUserId()).Email;
            ViewBag.sender = "ManageProfile";
            return View("index");
        }
        [ValidateAntiForgeryToken]
        [HttpPost]
        public ActionResult ChangeEmail([Bind(Include = "Id,Email,EmailConfirmed,PasswordHash,SecurityStamp,PhoneNumber,PhoneNumberConfirmed,TwoFactorEnabled,LockoutEndDateUtc,LockoutEnabled,AccessFailedCount,UserName,user_image,Id_Image,National_Number,HighSchool_Image,HighSchool_Avg,First_Name,Last_Name,Major_Id,IsAccepted,Balance")] AspNetUser aspNetUser, string ChangeEmail)
        {
            if (!string.IsNullOrEmpty(ChangeEmail))
            {


                var phon = db.AspNetUsers.Find(User.Identity.GetUserId());

                phon.Email = ChangeEmail;
               
                db.SaveChanges();
            }
            ViewBag.PhoneNumber = db.AspNetUsers.Find(User.Identity.GetUserId()).PhoneNumber;
            ViewBag.CurrentBalance = db.AspNetUsers.Find(User.Identity.GetUserId()).Balance;
            ViewBag.Email = db.AspNetUsers.Find(User.Identity.GetUserId()).Email;
            ViewBag.sender = "ManageProfile";
            return View("index");
        }
        [Authorize(Roles = "Student")]
        public ActionResult Registration()
        {
            string userid = User.Identity.GetUserId();
            var logstudent = db.AspNetUsers.Find(userid);
            int combalance = 9 * Convert.ToInt32(logstudent.Major.Price);
            var semisteres = db.semesters;
            int current = 1;
            bool test = true;
            foreach (var semester in semisteres)
            {
                if (semester.end_date > DateTime.Now.Date && semester.start_date < DateTime.Now.Date)
                {
                    current = semester.id;
                    test = false;
                }
            }
            if (test)
            {
                string Error1 = $"You should be in the registration period";
                return RedirectToAction("Errors", new { Error = Error1 });
            }

            var dates1 = db.RegistrationPeriods.First(x => x.semester_id == current);
            if (DateTime.Now.Date <= dates1.start_date && DateTime.Now.Date >= dates1.end_date)
            {
                string Error1 = $"You should be in the registration period";
                return RedirectToAction("Errors", new { Error = Error1 });

            }
            if (logstudent.Balance < combalance)
            {
                string Error = $"You dont have the min balance which is {combalance}";
                return RedirectToAction("Errors", new { Error = Error });
            }

            var currentregestered = db.Enrollments.Where(x => x.semester_id == current && x.Student_id == userid).Include(x => x.Courses_Offered.Cours).Include(x => x.Courses_Offered).ToList();
            return View(currentregestered);
        }

        [HttpPost]
        public ActionResult Registration(int? Course_id, int? delete)
        {
            //18 hours max
            string userid = User.Identity.GetUserId();
            var logstudent = db.AspNetUsers.Find(userid);
            int balancee = Convert.ToInt32(logstudent.Balance);
            int hourprice = Convert.ToInt32(logstudent.Major.Price);

            var semisteres = db.semesters;
            int current = 1;
            bool test = true;
            foreach (var semester in semisteres)
            {
                if (semester.end_date > DateTime.Now.Date && semester.start_date < DateTime.Now.Date)
                {
                    current = semester.id;
                    test = false;
                }
            }
            var currentregestered = db.Enrollments.Where(x => x.semester_id == current && x.Student_id == userid).Include(x => x.Courses_Offered.Cours).Include(x => x.Courses_Offered).ToList();

            var registerednow = db.Enrollments.Where(x => x.Student_id == userid && x.semester_id == current);

            if (delete != null)
            {
                var enroll = db.Enrollments.Find(delete);
                var selectedcourse2 = db.Courses_Offered.Find(enroll.Course_id);
                int hourss = Convert.ToInt32(enroll.Courses_Offered.Cours.Number_Of_Hours);
                logstudent.Balance = balancee + hourss * hourprice;
                db.Enrollments.Remove(enroll);
                int counter2 = Convert.ToInt32(selectedcourse2.Registered);
                selectedcourse2.Registered = counter2 - 1;
                db.SaveChanges();
                currentregestered = db.Enrollments.Where(x => x.semester_id == current && x.Student_id == userid).Include(x => x.Courses_Offered.Cours).Include(x => x.Courses_Offered).ToList();
                return View(currentregestered);

            }

            var selectedcourse = db.Courses_Offered.Find(Course_id);
            if (selectedcourse == null)
            {
                TempData["swal_message"] = $"There is no Courses in the schedual with this id ";
                ViewBag.title = "Error";
                ViewBag.icon = "warning";
                return View(currentregestered);
            }

            int counthours = 0;
            foreach (var item in registerednow)
            {
                counthours += Convert.ToInt32(item.Courses_Offered.Cours.Number_Of_Hours);

            }
            if (counthours + selectedcourse.Cours.Number_Of_Hours > 18)
            {
                TempData["swal_message"] = $"You can't register more than 18 houre per semester ";
                ViewBag.title = "Error";
                ViewBag.icon = "warning";
                return View(currentregestered);
            }



            int hourenumber = Convert.ToInt32(selectedcourse.Cours.Number_Of_Hours);

            int combalance = 9 * Convert.ToInt32(logstudent.Major.Price);
            var coursesoffered = db.Courses_Offered.Where(x => x.semester_id == current && x.Cours.Major_Id == logstudent.Major_Id);
            bool ex1 = false;
            foreach (var courses in coursesoffered)
            {
                if (courses.course_id == selectedcourse.course_id)
                {
                    ex1 = true;
                }

            }
            if (!ex1)
            {
                TempData["swal_message"] = $"This course belong to other major";
                ViewBag.title = "Error";
                ViewBag.icon = "warning";
                return View(currentregestered);
            }
            foreach (var item in registerednow)
            {
                if (item.Courses_Offered.course_id == selectedcourse.Cours.Course_Id)
                {
                    TempData["swal_message"] = $"You already have this course ";
                    ViewBag.title = "Error";
                    ViewBag.icon = "warning";
                    return View(currentregestered);
                }
                if (selectedcourse.start_time < item.Courses_Offered.end_time && selectedcourse.end_time > item.Courses_Offered.start_time && selectedcourse.Days_id == item.Courses_Offered.Days_id)
                {
                    TempData["swal_message"] = $"Partial overlapping occured  ";
                    ViewBag.title = "Error";
                    ViewBag.icon = "warning";
                    return View(currentregestered);
                }

                else if (selectedcourse.start_time == item.Courses_Offered.start_time || selectedcourse.end_time == item.Courses_Offered.end_time && selectedcourse.Days_id == item.Courses_Offered.Days_id)
                {
                    TempData["swal_message"] = $"complete overlapping occured  ";
                    ViewBag.title = "Error";
                    ViewBag.icon = "warning";
                    return View(currentregestered);
                }


            }

            if (logstudent.Balance < hourenumber * hourprice)
            {
                TempData["swal_message"] = $"You dont have the enofh balance that is requiered for registration this course you should add   {hourenumber * hourprice - logstudent.Balance} ";
                ViewBag.title = "Error";
                ViewBag.icon = "warning";
                return View(currentregestered);
            }

            if (selectedcourse.Registered >= selectedcourse.Capacity)
            {
                TempData["swal_message"] = $"This course is full ";
                ViewBag.title = "Error";
                ViewBag.icon = "warning";
                return View(currentregestered);
            }

            bool ex = false;
            var allregisteredcourses = db.Enrollments.Where(x => x.Student_id == userid && x.semester_id == current);
            //Find();

            if (selectedcourse.Cours.dependent_Course != null)
            {
                var dependentcourse = db.Courses.Find(Convert.ToInt32(selectedcourse.Cours.dependent_Course));

                foreach (var item in allregisteredcourses)
                {
                    if (item.Course_id == dependentcourse.Course_Id)
                    {
                        ex = true;
                    }
                }
                if (!ex)
                {
                    TempData["swal_message"] = $"you dont have the prerequirement which is {dependentcourse.Course_Name} ";
                    ViewBag.title = "Error";
                    ViewBag.icon = "warning";
                    return View(currentregestered);

                }
            }
            Enrollment addcourse = new Enrollment();
            addcourse.semester_id = current;
            addcourse.Course_id = Course_id;
            addcourse.Student_id = userid;
            addcourse.Is_Paid = false;

            db.Enrollments.Add(addcourse);
            db.SaveChanges();
            logstudent.Balance = balancee - hourenumber * hourprice;
            int counter = Convert.ToInt32(selectedcourse.Registered);
            selectedcourse.Registered = counter + 1;
            db.SaveChanges();
            TempData["swal_message"] = $"you dont have registered this course successfully ";
            ViewBag.title = "success";
            ViewBag.icon = "success";
            var currentregestered2 = db.Enrollments.Where(x => x.semester_id == current && x.Student_id == userid).Include(x => x.Courses_Offered.Cours).Include(x => x.Courses_Offered).ToList();
            return View(currentregestered2);

        }

        public ActionResult schedule()
        {
            var semesteres = db.semesters.ToList();
            var majors = db.Majors.ToList();
            dynamic all = new ExpandoObject();
            all.m = majors;
            all.s = semesteres;
            ViewBag.messege = "get";
            return View(all);
        }

        [HttpPost]
        public ActionResult schedule(int semesterid, int majorid)
        {
            var semesteres = db.semesters.ToList();
            var majors = db.Majors.ToList();
            dynamic all = new ExpandoObject();
            all.m = majors;
            all.s = semesteres;
            ViewBag.semesterid = semesterid;
            ViewBag.majorid = majorid;
            var allcourses = db.Courses_Offered.Where(x => x.Cours.Major_Id == majorid && x.semester_id == semesterid).ToList();
            all.a = allcourses;
            return View(all);
        }
        public ActionResult Errors(string Error)
        {
            if (Error == null)
            {
                ViewBag.message = "No Errors";
                return View();
            }
            ViewBag.message = Error;
            return View();
        }
        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private bool HasPassword()
        {
            var user = UserManager.FindById(User.Identity.GetUserId());
            if (user != null)
            {
                return user.PasswordHash != null;
            }
            return false;
        }

        private bool HasPhoneNumber()
        {
            var user = UserManager.FindById(User.Identity.GetUserId());
            if (user != null)
            {
                return user.PhoneNumber != null;
            }
            return false;
        }

        public enum ManageMessageId
        {
            AddPhoneSuccess,
            ChangePasswordSuccess,
            SetTwoFactorSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            RemovePhoneSuccess,
            Error
        }
        #endregion
    }
}