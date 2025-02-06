function validateForm() {

    //This will collect all the information from the form

      const email    = document.querySelector('[name="email"]').value.trim();
      const username = document.querySelector('[name="username"]').value.trim();
      const password = document.querySelector('[name="password"]').value;
      
      
      //this we will add to our form later
      const errorDisplay = document.getElementById('client-errors');
    
       // Clear any old error messages before we begin
      errorDisplay.textContent = '';
    
      // We'll collect errors in an array and display them all at once
          const errors = [];
     
      //Check username length
      if (username.length < 3) {
        errors.push("Username must be at least 3 characters long.");
      }
      
        if (errors.length > 0) {
        // Join the errors into a single string.
        errorDisplay.textContent = errors.join(' ');
        return false; // Prevent submission
      }
    
        // If no errors, let the form submit
      return true;
      }
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        errors.push("Please enter a valid email address.");
      }