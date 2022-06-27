import { HttpClientModule, HTTP_INTERCEPTORS } from "@angular/common/http";
import { NgModule } from "@angular/core";
import { FormsModule } from "@angular/forms";
import { BrowserModule } from "@angular/platform-browser";
import { AppRoutingModule } from "./app-routing.module";
import { AppComponent } from "./app.component";
import { AuthenticationGuard } from "./guard/authentication.guard";
import { AuthInterceptor } from "./interceptor/auth.interceptor";
import { LoginComponent } from "./login/login.component";
import { NotificationModule } from "./notification.module";
import { RegisterComponent } from "./register/register.component";
import { AuthenticationService } from "./service/authentication.service";
import { NotificationService } from "./service/notification.service";
import { UserService } from "./service/user.service";
import { UserComponent } from "./user/user.component";


@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    RegisterComponent,
    UserComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    HttpClientModule,
    NotificationModule
  ],
  providers: [NotificationService, AuthenticationGuard, AuthenticationService, UserService,
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true } ],
  bootstrap: [AppComponent]
})
export class AppModule { }
