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
import type { FieldEActivesessionEzsign } from './field-eactivesession-ezsign';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEActivesessionEzsignaccess } from './field-eactivesession-ezsignaccess';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEActivesessionEzsignprepaid } from './field-eactivesession-ezsignprepaid';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEActivesessionOrigin } from './field-eactivesession-origin';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEActivesessionRealestateinprogress } from './field-eactivesession-realestateinprogress';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEActivesessionUsertype } from './field-eactivesession-usertype';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEActivesessionWeekdaystart } from './field-eactivesession-weekdaystart';

/**
 * An Activesession Object
 * @export
 * @interface ActivesessionResponse
 */
export interface ActivesessionResponse {
    /**
     * 
     * @type {FieldEActivesessionUsertype}
     * @memberof ActivesessionResponse
     */
    /*'eActivesessionUsertype': FieldEActivesessionUsertype;*/
    'eActivesessionUsertype': FieldEActivesessionUsertype;
    /**
     * 
     * @type {FieldEActivesessionOrigin}
     * @memberof ActivesessionResponse
     */
    /*'eActivesessionOrigin': FieldEActivesessionOrigin;*/
    'eActivesessionOrigin': FieldEActivesessionOrigin;
    /**
     * 
     * @type {FieldEActivesessionWeekdaystart}
     * @memberof ActivesessionResponse
     */
    /*'eActivesessionWeekdaystart': FieldEActivesessionWeekdaystart;*/
    'eActivesessionWeekdaystart': FieldEActivesessionWeekdaystart;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof ActivesessionResponse
     */
    /*'fkiLanguageID': number;*/
    'fkiLanguageID': number;
    /**
     * The Name of the Company in the language of the requester
     * @type {string}
     * @memberof ActivesessionResponse
     */
    /*'sCompanyNameX': string;*/
    'sCompanyNameX': string;
    /**
     * The Name of the Department in the language of the requester
     * @type {string}
     * @memberof ActivesessionResponse
     */
    /*'sDepartmentNameX': string;*/
    'sDepartmentNameX': string;
    /**
     * Whether the active session is in debug or not
     * @type {boolean}
     * @memberof ActivesessionResponse
     */
    /*'bActivesessionDebug': boolean;*/
    'bActivesessionDebug': boolean;
    /**
     * Whether the active session is superadmin or not
     * @type {boolean}
     * @memberof ActivesessionResponse
     */
    /*'bActivesessionIssuperadmin': boolean;*/
    'bActivesessionIssuperadmin': boolean;
    /**
     * Can access attachment when we clone a user
     * @type {boolean}
     * @memberof ActivesessionResponse
     */
    /*'bActivesessionAttachment'?: boolean;*/
    'bActivesessionAttachment'?: boolean;
    /**
     * Can access canafe when we clone a user
     * @type {boolean}
     * @memberof ActivesessionResponse
     */
    /*'bActivesessionCanafe'?: boolean;*/
    'bActivesessionCanafe'?: boolean;
    /**
     * Can access financial element when we clone a user
     * @type {boolean}
     * @memberof ActivesessionResponse
     */
    /*'bActivesessionFinancial'?: boolean;*/
    'bActivesessionFinancial'?: boolean;
    /**
     * Can access closed realestate folders when we clone a user
     * @type {boolean}
     * @memberof ActivesessionResponse
     */
    /*'bActivesessionRealestatecompleted'?: boolean;*/
    'bActivesessionRealestatecompleted'?: boolean;
    /**
     * 
     * @type {FieldEActivesessionEzsign}
     * @memberof ActivesessionResponse
     */
    /*'eActivesessionEzsign'?: FieldEActivesessionEzsign;*/
    'eActivesessionEzsign'?: FieldEActivesessionEzsign;
    /**
     * 
     * @type {FieldEActivesessionEzsignaccess}
     * @memberof ActivesessionResponse
     */
    /*'eActivesessionEzsignaccess': FieldEActivesessionEzsignaccess;*/
    'eActivesessionEzsignaccess': FieldEActivesessionEzsignaccess;
    /**
     * 
     * @type {FieldEActivesessionEzsignprepaid}
     * @memberof ActivesessionResponse
     */
    /*'eActivesessionEzsignprepaid'?: FieldEActivesessionEzsignprepaid;*/
    'eActivesessionEzsignprepaid'?: FieldEActivesessionEzsignprepaid;
    /**
     * 
     * @type {FieldEActivesessionRealestateinprogress}
     * @memberof ActivesessionResponse
     */
    /*'eActivesessionRealestateinprogress'?: FieldEActivesessionRealestateinprogress;*/
    'eActivesessionRealestateinprogress'?: FieldEActivesessionRealestateinprogress;
    /**
     * The customer code assigned to your account
     * @type {string}
     * @memberof ActivesessionResponse
     */
    /*'pksCustomerCode': string;*/
    'pksCustomerCode': string;
    /**
     * The unique ID of the Systemconfigurationtype
     * @type {number}
     * @memberof ActivesessionResponse
     */
    /*'fkiSystemconfigurationtypeID': number;*/
    'fkiSystemconfigurationtypeID': number;
    /**
     * The unique ID of the Signature
     * @type {number}
     * @memberof ActivesessionResponse
     */
    /*'fkiSignatureID'?: number;*/
    'fkiSignatureID'?: number;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ActivesessionResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectActivesessionResponse
 */
export class DataObjectActivesessionResponse {
   eActivesessionUsertype:FieldEActivesessionUsertype = 'AgentBroker'
   eActivesessionOrigin:FieldEActivesessionOrigin = 'BuiltIn'
   eActivesessionWeekdaystart:FieldEActivesessionWeekdaystart = 'Sunday'
   fkiLanguageID:number = 0
   sCompanyNameX:string = ''
   sDepartmentNameX:string = ''
   bActivesessionDebug:boolean = false
   bActivesessionIssuperadmin:boolean = false
   bActivesessionAttachment?:boolean = undefined
   bActivesessionCanafe?:boolean = undefined
   bActivesessionFinancial?:boolean = undefined
   bActivesessionRealestatecompleted?:boolean = undefined
   eActivesessionEzsign?:FieldEActivesessionEzsign = undefined
   eActivesessionEzsignaccess:FieldEActivesessionEzsignaccess = 'No'
   eActivesessionEzsignprepaid?:FieldEActivesessionEzsignprepaid = undefined
   eActivesessionRealestateinprogress?:FieldEActivesessionRealestateinprogress = undefined
   pksCustomerCode:string = ''
   fkiSystemconfigurationtypeID:number = 0
   fkiSignatureID?:number = undefined
}

/**
 * @export 
 * A ActivesessionResponse Validation Object
 * @class ValidationObjectActivesessionResponse
 */
export class ValidationObjectActivesessionResponse {
   eActivesessionUsertype = {
      type: 'enum',
      allowableValues: ['AgentBroker','Assistant','EzsignSigner','EzsignUser','Normal'],
      required: true
   }
   eActivesessionOrigin = {
      type: 'enum',
      allowableValues: ['BuiltIn','External'],
      required: true
   }
   eActivesessionWeekdaystart = {
      type: 'enum',
      allowableValues: ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'],
      required: true
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   sCompanyNameX = {
      type: 'string',
      required: true
   }
   sDepartmentNameX = {
      type: 'string',
      required: true
   }
   bActivesessionDebug = {
      type: 'boolean',
      required: true
   }
   bActivesessionIssuperadmin = {
      type: 'boolean',
      required: true
   }
   bActivesessionAttachment = {
      type: 'boolean',
      required: false
   }
   bActivesessionCanafe = {
      type: 'boolean',
      required: false
   }
   bActivesessionFinancial = {
      type: 'boolean',
      required: false
   }
   bActivesessionRealestatecompleted = {
      type: 'boolean',
      required: false
   }
   eActivesessionEzsign = {
      type: 'enum',
      allowableValues: ['No','Read','Modify','Full'],
      required: false
   }
   eActivesessionEzsignaccess = {
      type: 'enum',
      allowableValues: ['No','PaidByOffice','PerDocument','Prepaid'],
      required: true
   }
   eActivesessionEzsignprepaid = {
      type: 'enum',
      allowableValues: ['No','Basic','Standard','Pro'],
      required: false
   }
   eActivesessionRealestateinprogress = {
      type: 'enum',
      allowableValues: ['No','Read','Modify','Create'],
      required: false
   }
   pksCustomerCode = {
      type: 'string',
      minLength: 2,
      maxLength: 6,
      required: true
   }
   fkiSystemconfigurationtypeID = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   fkiSignatureID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
} 


