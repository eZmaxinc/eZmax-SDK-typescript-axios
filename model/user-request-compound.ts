/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
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
/*export type UserRequestCompound = UserRequest;*/
export interface UserRequestCompound {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof UserRequestCompound
     */
    pkiUserID?:number 
    /**
     * The unique ID of the Agent.
     * @type {number}
     * @memberof UserRequestCompound
     */
    fkiAgentID?:number 
    /**
     * The unique ID of the Broker.
     * @type {number}
     * @memberof UserRequestCompound
     */
    fkiBrokerID?:number 
    /**
     * The unique ID of the Assistant.
     * @type {number}
     * @memberof UserRequestCompound
     */
    fkiAssistantID?:number 
    /**
     * The unique ID of the Employee.
     * @type {number}
     * @memberof UserRequestCompound
     */
    fkiEmployeeID?:number 
    /**
     * The unique ID of the Company
     * @type {number}
     * @memberof UserRequestCompound
     */
    fkiCompanyIDDefault:number 
    /**
     * The unique ID of the Department
     * @type {number}
     * @memberof UserRequestCompound
     */
    fkiDepartmentIDDefault:number 
    /**
     * The unique ID of the Timezone
     * @type {number}
     * @memberof UserRequestCompound
     */
    fkiTimezoneID:number 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof UserRequestCompound
     */
    fkiLanguageID:number 
    /**
     * 
     * @type {EmailRequestCompound}
     * @memberof UserRequestCompound
     */
    objEmail:EmailRequestCompound 
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof UserRequestCompound
     */
    fkiBillingentityinternalID:number 
    /**
     * 
     * @type {PhoneRequestCompound}
     * @memberof UserRequestCompound
     */
    objPhoneHome?:PhoneRequestCompound 
    /**
     * 
     * @type {PhoneRequestCompound}
     * @memberof UserRequestCompound
     */
    objPhoneSMS?:PhoneRequestCompound 
    /**
     * The unique ID of the Secretquestion.  Valid values:  |Value|Description| |-|-| |1|The name of the hospital in which you were born| |2|The name of your grade school| |3|The last name of your favorite teacher| |4|Your favorite sports team| |5|Your favorite TV show| |6|Your favorite movie| |7|The name of the street on which you grew up| |8|The name of your first employer| |9|Your first car| |10|Your favorite food| |11|The name of your first pet| |12|Favorite musician/band| |13|What instrument you play| |14|Your father\'s middle name| |15|Your mother\'s maiden name| |16|Name of your eldest child| |17|Your spouse\'s middle name| |18|Favorite restaurant| |19|Childhood nickname| |20|Favorite vacation destination| |21|Your boat\'s name| |22|Date of Birth (YYYY-MM-DD)| |22|Secret Code| |22|Your reference code|
     * @type {number}
     * @memberof UserRequestCompound
     */
    fkiSecretquestionID?:number 
    /**
     * The answer to the Secretquestion
     * @type {string}
     * @memberof UserRequestCompound
     */
    sUserSecretresponse?:string 
    /**
     * The unique ID of the Module
     * @type {number}
     * @memberof UserRequestCompound
     */
    fkiModuleIDForm?:number 
    /**
     * 
     * @type {FieldEUserType}
     * @memberof UserRequestCompound
     */
    eUserType:FieldEUserType 
    /**
     * 
     * @type {FieldEUserLogintype}
     * @memberof UserRequestCompound
     */
    eUserLogintype:FieldEUserLogintype 
    /**
     * The first name of the user
     * @type {string}
     * @memberof UserRequestCompound
     */
    sUserFirstname:string 
    /**
     * The last name of the user
     * @type {string}
     * @memberof UserRequestCompound
     */
    sUserLastname:string 
    /**
     * The login name of the User.
     * @type {string}
     * @memberof UserRequestCompound
     */
    sUserLoginname:string 
    /**
     * The job title of the user
     * @type {string}
     * @memberof UserRequestCompound
     */
    sUserJobtitle?:string 
    /**
     * 
     * @type {FieldEUserEzsignaccess}
     * @memberof UserRequestCompound
     */
    eUserEzsignaccess:FieldEUserEzsignaccess 
    /**
     * Whether the User is active or not
     * @type {boolean}
     * @memberof UserRequestCompound
     */
    bUserIsactive:boolean 
    /**
     * Whether if the transactions in which the User is implicated must be validated by administrative personnel or not
     * @type {boolean}
     * @memberof UserRequestCompound
     */
    bUserValidatebyadministration?:boolean 
    /**
     * Whether if the transactions in which the User is implicated must be validated by a director or not
     * @type {boolean}
     * @memberof UserRequestCompound
     */
    bUserValidatebydirector?:boolean 
    /**
     * Whether if Attachments uploaded by the User must be validated or not
     * @type {boolean}
     * @memberof UserRequestCompound
     */
    bUserAttachmentautoverified?:boolean 
    /**
     * Whether if the User is forced to change its password
     * @type {boolean}
     * @memberof UserRequestCompound
     */
    bUserChangepassword?:boolean 
}



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
    sUserJobtitle?:string = undefined
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
      pattern: '/^(?:([\w.%+\-!#$%&amp;&#39;*+\\/&#x3D;?^&#x60;{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20})|([a-zA-Z0-9]){1,32})$/',
      required: true
   }
   sUserJobtitle = {
      type: 'string',
      pattern: '/^.{0,50}$/',
      required: false
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


