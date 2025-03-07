/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import type { EmailResponseCompound } from './email-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEUserEzsignaccess } from './field-euser-ezsignaccess';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEUserLogintype } from './field-euser-logintype';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEUserOrigin } from './field-euser-origin';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEUserType } from './field-euser-type';
// May contain unused imports in some cases
// @ts-ignore
import type { PhoneResponseCompound } from './phone-response-compound';

/**
 * A User Object
 * @export
 * @interface UserResponse
 */
export interface UserResponse {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof UserResponse
     */
    /*'pkiUserID': number;*/
    'pkiUserID': number;
    /**
     * The unique ID of the Agent.
     * @type {number}
     * @memberof UserResponse
     */
    /*'fkiAgentID'?: number;*/
    'fkiAgentID'?: number;
    /**
     * The unique ID of the Broker.
     * @type {number}
     * @memberof UserResponse
     */
    /*'fkiBrokerID'?: number;*/
    'fkiBrokerID'?: number;
    /**
     * The unique ID of the Assistant.
     * @type {number}
     * @memberof UserResponse
     */
    /*'fkiAssistantID'?: number;*/
    'fkiAssistantID'?: number;
    /**
     * The unique ID of the Employee.
     * @type {number}
     * @memberof UserResponse
     */
    /*'fkiEmployeeID'?: number;*/
    'fkiEmployeeID'?: number;
    /**
     * The unique ID of the Company
     * @type {number}
     * @memberof UserResponse
     */
    /*'fkiCompanyIDDefault': number;*/
    'fkiCompanyIDDefault': number;
    /**
     * The Name of the Company in the language of the requester
     * @type {string}
     * @memberof UserResponse
     */
    /*'sCompanyNameX': string;*/
    'sCompanyNameX': string;
    /**
     * The unique ID of the Department
     * @type {number}
     * @memberof UserResponse
     */
    /*'fkiDepartmentIDDefault': number;*/
    'fkiDepartmentIDDefault': number;
    /**
     * The Name of the Department in the language of the requester
     * @type {string}
     * @memberof UserResponse
     */
    /*'sDepartmentNameX': string;*/
    'sDepartmentNameX': string;
    /**
     * The unique ID of the Timezone
     * @type {number}
     * @memberof UserResponse
     */
    /*'fkiTimezoneID': number;*/
    'fkiTimezoneID': number;
    /**
     * The description of the Timezone
     * @type {string}
     * @memberof UserResponse
     */
    /*'sTimezoneName': string;*/
    'sTimezoneName': string;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof UserResponse
     */
    /*'fkiLanguageID': number;*/
    'fkiLanguageID': number;
    /**
     * The Name of the Language in the language of the requester
     * @type {string}
     * @memberof UserResponse
     */
    /*'sLanguageNameX': string;*/
    'sLanguageNameX': string;
    /**
     * 
     * @type {EmailResponseCompound}
     * @memberof UserResponse
     */
    /*'objEmail': EmailResponseCompound;*/
    'objEmail': EmailResponseCompound;
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof UserResponse
     */
    /*'fkiBillingentityinternalID': number;*/
    'fkiBillingentityinternalID': number;
    /**
     * The description of the Billingentityinternal in the language of the requester
     * @type {string}
     * @memberof UserResponse
     */
    /*'sBillingentityinternalDescriptionX': string;*/
    'sBillingentityinternalDescriptionX': string;
    /**
     * 
     * @type {PhoneResponseCompound}
     * @memberof UserResponse
     */
    /*'objPhoneHome'?: PhoneResponseCompound;*/
    'objPhoneHome'?: PhoneResponseCompound;
    /**
     * 
     * @type {PhoneResponseCompound}
     * @memberof UserResponse
     */
    /*'objPhoneSMS'?: PhoneResponseCompound;*/
    'objPhoneSMS'?: PhoneResponseCompound;
    /**
     * The unique ID of the Secretquestion.  Valid values:  |Value|Description| |-|-| |1|The name of the hospital in which you were born| |2|The name of your grade school| |3|The last name of your favorite teacher| |4|Your favorite sports team| |5|Your favorite TV show| |6|Your favorite movie| |7|The name of the street on which you grew up| |8|The name of your first employer| |9|Your first car| |10|Your favorite food| |11|The name of your first pet| |12|Favorite musician/band| |13|What instrument you play| |14|Your father\'s middle name| |15|Your mother\'s maiden name| |16|Name of your eldest child| |17|Your spouse\'s middle name| |18|Favorite restaurant| |19|Childhood nickname| |20|Favorite vacation destination| |21|Your boat\'s name| |22|Date of Birth (YYYY-MM-DD)| |22|Secret Code| |22|Your reference code|
     * @type {number}
     * @memberof UserResponse
     */
    /*'fkiSecretquestionID'?: number;*/
    'fkiSecretquestionID'?: number;
    /**
     * The unique ID of the Module
     * @type {number}
     * @memberof UserResponse
     */
    /*'fkiModuleIDForm'?: number;*/
    'fkiModuleIDForm'?: number;
    /**
     * The Name of the Module in the language of the requester
     * @type {string}
     * @memberof UserResponse
     */
    /*'sModuleNameX'?: string;*/
    'sModuleNameX'?: string;
    /**
     * 
     * @type {FieldEUserOrigin}
     * @memberof UserResponse
     */
    /*'eUserOrigin': FieldEUserOrigin;*/
    'eUserOrigin': FieldEUserOrigin;
    /**
     * 
     * @type {FieldEUserType}
     * @memberof UserResponse
     */
    /*'eUserType': FieldEUserType;*/
    'eUserType': FieldEUserType;
    /**
     * 
     * @type {FieldEUserLogintype}
     * @memberof UserResponse
     */
    /*'eUserLogintype': FieldEUserLogintype;*/
    'eUserLogintype': FieldEUserLogintype;
    /**
     * The first name of the user
     * @type {string}
     * @memberof UserResponse
     */
    /*'sUserFirstname': string;*/
    'sUserFirstname': string;
    /**
     * The last name of the user
     * @type {string}
     * @memberof UserResponse
     */
    /*'sUserLastname': string;*/
    'sUserLastname': string;
    /**
     * The login name of the User.
     * @type {string}
     * @memberof UserResponse
     */
    /*'sUserLoginname': string;*/
    'sUserLoginname': string;
    /**
     * The job title of the user
     * @type {string}
     * @memberof UserResponse
     */
    /*'sUserJobtitle'?: string;*/
    'sUserJobtitle'?: string;
    /**
     * 
     * @type {FieldEUserEzsignaccess}
     * @memberof UserResponse
     */
    /*'eUserEzsignaccess': FieldEUserEzsignaccess;*/
    'eUserEzsignaccess': FieldEUserEzsignaccess;
    /**
     * The last logon date of the User
     * @type {string}
     * @memberof UserResponse
     */
    /*'dtUserLastlogondate'?: string;*/
    'dtUserLastlogondate'?: string;
    /**
     * The date at which the User\'s password was last changed
     * @type {string}
     * @memberof UserResponse
     */
    /*'dtUserPasswordchanged'?: string;*/
    'dtUserPasswordchanged'?: string;
    /**
     * The eZsign prepaid expiration date
     * @type {string}
     * @memberof UserResponse
     */
    /*'dtUserEzsignprepaidexpiration'?: string;*/
    'dtUserEzsignprepaidexpiration'?: string;
    /**
     * Whether the User is active or not
     * @type {boolean}
     * @memberof UserResponse
     */
    /*'bUserIsactive': boolean;*/
    'bUserIsactive': boolean;
    /**
     * Whether if the transactions in which the User is implicated must be validated by administrative personnel or not
     * @type {boolean}
     * @memberof UserResponse
     */
    /*'bUserValidatebyadministration'?: boolean;*/
    'bUserValidatebyadministration'?: boolean;
    /**
     * Whether if the transactions in which the User is implicated must be validated by a director or not
     * @type {boolean}
     * @memberof UserResponse
     */
    /*'bUserValidatebydirector'?: boolean;*/
    'bUserValidatebydirector'?: boolean;
    /**
     * Whether if Attachments uploaded by the User must be validated or not
     * @type {boolean}
     * @memberof UserResponse
     */
    /*'bUserAttachmentautoverified'?: boolean;*/
    'bUserAttachmentautoverified'?: boolean;
    /**
     * Whether if the User is forced to change its password
     * @type {boolean}
     * @memberof UserResponse
     */
    /*'bUserChangepassword': boolean;*/
    'bUserChangepassword': boolean;
    /**
     * 
     * @type {CommonAudit}
     * @memberof UserResponse
     */
    /*'objAudit': CommonAudit;*/
    'objAudit': CommonAudit;
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEmailResponseCompound } from './'
// @ts-ignore
import { DataObjectPhoneResponseCompound } from './'
// @ts-ignore
import { DataObjectPhoneResponseCompound } from './'
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectEmailResponseCompound } from './'
// @ts-ignore
import { ValidationObjectPhoneResponseCompound } from './'
// @ts-ignore
import { ValidationObjectPhoneResponseCompound } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A UserResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserResponse
 */
export class DataObjectUserResponse {
   pkiUserID:number = 0
   fkiAgentID?:number = undefined
   fkiBrokerID?:number = undefined
   fkiAssistantID?:number = undefined
   fkiEmployeeID?:number = undefined
   fkiCompanyIDDefault:number = 0
   sCompanyNameX:string = ''
   fkiDepartmentIDDefault:number = 0
   sDepartmentNameX:string = ''
   fkiTimezoneID:number = 0
   sTimezoneName:string = ''
   fkiLanguageID:number = 0
   sLanguageNameX:string = ''
   objEmail:EmailResponseCompound = new DataObjectEmailResponseCompound()
   fkiBillingentityinternalID:number = 0
   sBillingentityinternalDescriptionX:string = ''
   objPhoneHome?:PhoneResponseCompound = undefined
   objPhoneSMS?:PhoneResponseCompound = undefined
   fkiSecretquestionID?:number = undefined
   fkiModuleIDForm?:number = undefined
   sModuleNameX?:string = undefined
   eUserOrigin:FieldEUserOrigin = 'BuiltIn'
   eUserType:FieldEUserType = 'AgentBroker'
   eUserLogintype:FieldEUserLogintype = 'Password'
   sUserFirstname:string = ''
   sUserLastname:string = ''
   sUserLoginname:string = ''
   sUserJobtitle?:string = undefined
   eUserEzsignaccess:FieldEUserEzsignaccess = 'No'
   dtUserLastlogondate?:string = undefined
   dtUserPasswordchanged?:string = undefined
   dtUserEzsignprepaidexpiration?:string = undefined
   bUserIsactive:boolean = false
   bUserValidatebyadministration?:boolean = undefined
   bUserValidatebydirector?:boolean = undefined
   bUserAttachmentautoverified?:boolean = undefined
   bUserChangepassword:boolean = false
   objAudit:CommonAudit = new DataObjectCommonAudit()
}

/**
 * @export 
 * A UserResponse Validation Object
 * @class ValidationObjectUserResponse
 */
export class ValidationObjectUserResponse {
   pkiUserID = {
      type: 'integer',
      minimum: 0,
      required: true
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
   sCompanyNameX = {
      type: 'string',
      required: true
   }
   fkiDepartmentIDDefault = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sDepartmentNameX = {
      type: 'string',
      required: true
   }
   fkiTimezoneID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sTimezoneName = {
      type: 'string',
      required: true
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   sLanguageNameX = {
      type: 'string',
      required: true
   }
   objEmail = new ValidationObjectEmailResponseCompound()
   fkiBillingentityinternalID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sBillingentityinternalDescriptionX = {
      type: 'string',
      required: true
   }
   objPhoneHome = new ValidationObjectPhoneResponseCompound()
   objPhoneSMS = new ValidationObjectPhoneResponseCompound()
   fkiSecretquestionID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiModuleIDForm = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sModuleNameX = {
      type: 'string',
      required: false
   }
   eUserOrigin = {
      type: 'enum',
      allowableValues: ['BuiltIn','External'],
      required: true
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
      pattern: /^(?:([\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20})|([a-zA-Z0-9]){1,32})$/,
      required: true
   }
   sUserJobtitle = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
   eUserEzsignaccess = {
      type: 'enum',
      allowableValues: ['No','PaidByOffice','PerDocument','Prepaid'],
      required: true
   }
   dtUserLastlogondate = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: false
   }
   dtUserPasswordchanged = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: false
   }
   dtUserEzsignprepaidexpiration = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/,
      required: false
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
      required: true
   }
   objAudit = new ValidationObjectCommonAudit()
} 


