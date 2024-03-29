/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EmailRequestCompound } from './email-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEUserEzsignaccess } from './field-euser-ezsignaccess';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEUserLogintype } from './field-euser-logintype';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEUserType } from './field-euser-type';
// May contain unused imports in some cases
// @ts-ignore
import { PhoneRequestCompound } from './phone-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { UserRequest } from './user-request';

/**
 * @type UserRequestCompound
 * A User Object and children
 * @export
 */
export type UserRequestCompound = UserRequest;



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEmailRequestCompound } from './'
// @ts-ignore
import { DataObjectPhoneRequestCompound } from './'
// @ts-ignore
import { DataObjectPhoneRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEmailRequestCompound } from './'
// @ts-ignore
import { ValidationObjectPhoneRequestCompound } from './'
// @ts-ignore
import { ValidationObjectPhoneRequestCompound } from './'

/**
 * @export 
 * A UserRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserRequestCompound
 */
export class DataObjectUserRequestCompound {
    pkiUserID?:number = undefined
    fkiAgentID?:number = undefined
    fkiBrokerID?:number = undefined
    fkiAssistantID?:number = undefined
    fkiEmployeeID?:number = undefined
    fkiCompanyIDDefault:number = 0
    fkiDepartmentIDDefault:number = 0
    fkiTimezoneID:number = 0
    fkiLanguageID:number = 0
    objEmail:EmailRequestCompound = new DataObjectEmailRequestCompound()
    fkiBillingentityinternalID:number = 0
    objPhoneHome?:PhoneRequestCompound = undefined
    objPhoneSMS?:PhoneRequestCompound = undefined
    fkiSecretquestionID?:number = undefined
    sUserSecretresponse?:string = undefined
    fkiModuleIDForm?:number = undefined
    eUserType:FieldEUserType = 'AgentBroker'
    eUserLogintype:FieldEUserLogintype = 'Password'
    sUserFirstname:string = ''
    sUserLastname:string = ''
    sUserLoginname:string = ''
    eUserEzsignaccess:FieldEUserEzsignaccess = 'No'
    bUserIsactive:boolean = false
    bUserValidatebyadministration?:boolean = undefined
    bUserValidatebydirector?:boolean = undefined
    bUserAttachmentautoverified?:boolean = undefined
    bUserChangepassword?:boolean = undefined
}

/**
 * @export 
 * A UserRequestCompound Validation Object
 * @class ValidationObjectUserRequestCompound
 */
export class ValidationObjectUserRequestCompound {
   pkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiAgentID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiBrokerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiAssistantID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEmployeeID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiCompanyIDDefault = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: true
   }
   fkiDepartmentIDDefault = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiTimezoneID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   objEmail = new ValidationObjectEmailRequestCompound()
   fkiBillingentityinternalID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   objPhoneHome = new ValidationObjectPhoneRequestCompound()
   objPhoneSMS = new ValidationObjectPhoneRequestCompound()
   fkiSecretquestionID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sUserSecretresponse = {
      type: 'string',
      required: false
   }
   fkiModuleIDForm = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   eUserType = {
      type: 'enum',
      allowableValues: ['AgentBroker','Assistant','Employee','EzsignUser','Normal'],
      required: true
   }
   eUserLogintype = {
      type: 'enum',
      allowableValues: ['Password','PasswordPhone','PasswordQuestion'],
      required: true
   }
   sUserFirstname = {
      type: 'string',
      required: true
   }
   sUserLastname = {
      type: 'string',
      required: true
   }
   sUserLoginname = {
      type: 'string',
      pattern: '/^(?:([\w\.-]+@[\w\.-]+\.\w{2,4})|([a-zA-Z0-9]){1,32})$/',
      required: true
   }
   eUserEzsignaccess = {
      type: 'enum',
      allowableValues: ['No','PaidByOffice','PerDocument','Prepaid'],
      required: true
   }
   bUserIsactive = {
      type: 'boolean',
      required: true
   }
   bUserValidatebyadministration = {
      type: 'boolean',
      required: false
   }
   bUserValidatebydirector = {
      type: 'boolean',
      required: false
   }
   bUserAttachmentautoverified = {
      type: 'boolean',
      required: false
   }
   bUserChangepassword = {
      type: 'boolean',
      required: false
   }
} 


