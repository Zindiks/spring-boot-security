package com.basic.basicsec;

import com.basic.basicsec.jwt.JwtUtils;
import com.basic.basicsec.jwt.LoginRequest;
import com.basic.basicsec.jwt.LoginResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class GreetingController {

    private final JwtUtils jwtUtils;
    private final AuthenticationManager authenticationManager;

    public GreetingController(JwtUtils jwtUtils, AuthenticationManager authenticationManager) {
        this.jwtUtils = jwtUtils;
        this.authenticationManager = authenticationManager;
    }

    @GetMapping("/hello")
    @ResponseBody
    public Map<String, String> greeting(HttpServletRequest request, HttpServletResponse response) {
        String clientIp = request.getRemoteAddr();
        System.out.println("Client IP: " + clientIp);

        response.setStatus(201);
        Map<String,String> responseBody = new HashMap<>();

        responseBody.put("message", "Hello, World!");
        responseBody.put("1"  ,"34");


        return responseBody;

    }


    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    @GetMapping("/user")
    @ResponseBody
    public String user() {
        return "user";
    }


    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    @ResponseBody
    public String admin() {
        return "admin";
    }



    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){

        Authentication authentication;
        try{
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        }catch (AuthenticationException e){
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status",false);

            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles = userDetails
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        LoginResponse response = new LoginResponse(userDetails.getUsername(), roles,jwtToken);

        return ResponseEntity.ok(response);
    }

}
