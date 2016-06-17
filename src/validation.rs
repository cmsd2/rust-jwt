use std::collections::HashMap;

use std::result;
use std::sync::Arc;
use std::io;
use std::error;

quick_error! {
    #[derive(Clone, Debug)]
    pub enum ValidationError {
        IoError(err: Arc<Box<io::Error>>) {
            from()
            description("io error")
            display("I/O error: {}", err)
            cause(err.get_ref().unwrap())
        }
        
        Error(err: Arc<Box<error::Error + Send + Sync>>) {
            from()
            description("error")
            display("Error: {}", err)
            //cause(err)
        }
        
        ApplicationError(err: String) {
            description("application error")
            display("Application error: {}", err)
        }
        
        ValidationError(state: ValidationState) {
            description("validation error")
            display("validation error: {:?}", state)
        }
        
        MissingRequiredValue(value_name: String) {
            description("missing required value")
            display("missing required value: {}", value_name)
        }
        
        InvalidValue(msg: String) {
            description("invalid value")
            display("invalid value: {}", msg)
        }
    }
}

pub type ValidationResult<T> = result::Result<T, ValidationError>;

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub valid: bool,
    pub errors: Vec<ValidationError>,
}

impl Field {
    pub fn new(name: String, valid: bool) -> Field {
        Field {
            name: name,
            valid: valid,
            errors: vec![]
        }
    }
}

pub trait State {
    fn accept(&mut self, field_name: &str);
    fn reject(&mut self, field_name: &str, reason: ValidationError);
}

#[derive(Clone, Debug)]
pub struct ValidationState
{
    pub valid: bool,
    pub fields: HashMap<String, Field>,
    pub errors: Vec<ValidationError>,
}

impl Default for ValidationState {
    fn default() -> ValidationState {
        ValidationState::new()
    }
}

impl ValidationState {
    pub fn new() -> ValidationState {
        ValidationState {
            valid: true,
            fields: HashMap::new(),
            errors: vec![],
        }
    }
}

impl State for ValidationState {
    fn accept(&mut self, field_name: &str) {
        let mut field = self.fields.entry(field_name.to_owned()).or_insert(Field::new(field_name.to_owned(), true));
        field.valid = true;
    }
    
    fn reject(&mut self, field_name: &str, reason: ValidationError) {
        let mut field = self.fields.entry(field_name.to_owned()).or_insert(Field::new(field_name.to_owned(), false));
        field.valid = false;
        field.errors.push(reason);
        self.valid = false;
    }
}

pub trait Validator<M> {
    fn validate(&mut self, model: &M) -> ValidationResult<bool>;
}

pub trait Rule<T, S>
{
	fn validate(&self, input:&T, state: &mut S) -> ValidationResult<()>;
}

impl <T, S, F> Rule<T, S> for F
where F: Fn(&T, &mut S) -> ValidationResult<()>
{
    fn validate(&self, input:&T, state: &mut S) -> ValidationResult<()> {
        (*self)(input, state)
    }
}

pub struct ValidationSchema<M> {
    pub state: ValidationState,
    pub rules: Vec<Box<Rule<M, ValidationState>>>
}

impl <M> ValidationSchema<M> {
    pub fn new() -> Self {
        ValidationSchema {
            state: ValidationState::new(),
            rules: vec![],
        }
    }
    
    pub fn rule(&mut self, r: Box<Rule<M, ValidationState>>) 
    {
        self.rules.push(r)
    }
}

impl <M> Validator<M> for ValidationSchema<M> {
    fn validate(&mut self, model: &M) -> ValidationResult<bool> {
        for rule in self.rules.iter() {
            if let Err(err) = rule.validate(model, &mut self.state) {
                self.state.valid = false;
                self.state.errors.push(err);
            }
        }
        
        Ok(self.state.valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[allow(dead_code)]
    struct TestStruct {
        num: i32,
        text: String,
    }
    
    impl TestStruct {
        pub fn new<T>(num: i32, text: T) -> TestStruct where T: Into<String> {
            TestStruct {
                num: num,
                text: text.into(),
            }
        }
    }
    
    #[test]
    pub fn test_null_rule() {
        let mut v = ValidationSchema::<TestStruct>::new();
        
        v.rule(Box::new(|_m: &TestStruct, _vs: &mut ValidationState| {
            Ok(())
        }));
        
        let a = TestStruct::new(123, "hello");
        
        assert_eq!(v.validate(&a).unwrap_or(false), true);
    }
    
    #[test]
    pub fn test_accept_rule() {
        let mut v = ValidationSchema::<TestStruct>::new();
        
        v.rule(Box::new(|_m: &TestStruct, vs: &mut ValidationState| {
            vs.accept("field name");
            Ok(())
        }));
        
        let a = TestStruct::new(123, "hello");
        
        assert_eq!(v.validate(&a).unwrap_or(false), true);
    }
    
    #[test]
    pub fn test_reject_rule() {
        let mut v = ValidationSchema::<TestStruct>::new();
        
        v.rule(Box::new(|_m: &TestStruct, vs: &mut ValidationState| {
            vs.reject("field name", ValidationError::InvalidValue("test error".to_owned()));
            Ok(())
        }));
        
        let a = TestStruct::new(123, "hello");
        
        assert_eq!(v.validate(&a).unwrap_or(true), false);
    }
    
    #[test]
    pub fn test_err_rule() {
        let mut v = ValidationSchema::<TestStruct>::new();
        
        v.rule(Box::new(|_m: &TestStruct, _vs: &mut ValidationState| -> ValidationResult<()> {
            Err(ValidationError::ApplicationError("test error".to_owned()))
        }));
        
        let a = TestStruct::new(123, "hello");
        
        assert_eq!(v.validate(&a).unwrap_or(true), false);
        assert_eq!(v.state.errors.len(), 1);
        assert_eq!(format!("{}", v.state.errors.get(0).unwrap()), "Application error: test error");
    }
}