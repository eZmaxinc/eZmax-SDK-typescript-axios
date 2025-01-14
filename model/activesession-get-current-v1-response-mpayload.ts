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
import { ActivesessionResponseCompound } from './activesession-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { ActivesessionResponseCompoundApikey } from './activesession-response-compound-apikey';
// May contain unused imports in some cases
// @ts-ignore
import { ActivesessionResponseCompoundUser } from './activesession-response-compound-user';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEActivesessionEzsign } from './field-eactivesession-ezsign';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEActivesessionEzsignaccess } from './field-eactivesession-ezsignaccess';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEActivesessionEzsignprepaid } from './field-eactivesession-ezsignprepaid';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEActivesessionOrigin } from './field-eactivesession-origin';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEActivesessionRealestateinprogress } from './field-eactivesession-realestateinprogress';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEActivesessionUsertype } from './field-eactivesession-usertype';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEActivesessionWeekdaystart } from './field-eactivesession-weekdaystart';
// May contain unused imports in some cases
// @ts-ignore
import { FieldESystemconfigurationEzsignofficeplan } from './field-esystemconfiguration-ezsignofficeplan';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEUserEzsignaccess } from './field-euser-ezsignaccess';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEUserEzsignprepaid } from './field-euser-ezsignprepaid';

/**
 * @type ActivesessionGetCurrentV1ResponseMPayload
 * Payload for GET /1/object/activesession/getCurrent
 * @export
 */
/*export type ActivesessionGetCurrentV1ResponseMPayload = ActivesessionResponseCompound;*/
export interface ActivesessionGetCurrentV1ResponseMPayload {
    /**
     * 
     * @type {FieldEActivesessionUsertype}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    eActivesessionUsertype:FieldEActivesessionUsertype 
    /**
     * 
     * @type {FieldEActivesessionOrigin}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    eActivesessionOrigin:FieldEActivesessionOrigin 
    /**
     * 
     * @type {FieldEActivesessionWeekdaystart}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    eActivesessionWeekdaystart:FieldEActivesessionWeekdaystart 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    fkiLanguageID:number 
    /**
     * The Name of the Company in the language of the requester
     * @type {string}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    sCompanyNameX:string 
    /**
     * The Name of the Department in the language of the requester
     * @type {string}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    sDepartmentNameX:string 
    /**
     * Whether the active session is in debug or not
     * @type {boolean}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    bActivesessionDebug:boolean 
    /**
     * Whether the active session is superadmin or not
     * @type {boolean}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    bActivesessionIssuperadmin:boolean 
    /**
     * Can access attachment when we clone a user
     * @type {boolean}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    bActivesessionAttachment?:boolean 
    /**
     * Can access canafe when we clone a user
     * @type {boolean}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    bActivesessionCanafe?:boolean 
    /**
     * Can access financial element when we clone a user
     * @type {boolean}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    bActivesessionFinancial?:boolean 
    /**
     * Can access closed realestate folders when we clone a user
     * @type {boolean}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    bActivesessionRealestatecompleted?:boolean 
    /**
     * 
     * @type {FieldEActivesessionEzsign}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    eActivesessionEzsign?:FieldEActivesessionEzsign 
    /**
     * 
     * @type {FieldEActivesessionEzsignaccess}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    eActivesessionEzsignaccess:FieldEActivesessionEzsignaccess 
    /**
     * 
     * @type {FieldEActivesessionEzsignprepaid}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    eActivesessionEzsignprepaid?:FieldEActivesessionEzsignprepaid 
    /**
     * 
     * @type {FieldEActivesessionRealestateinprogress}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    eActivesessionRealestateinprogress?:FieldEActivesessionRealestateinprogress 
    /**
     * The customer code assigned to your account
     * @type {string}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    pksCustomerCode:string 
    /**
     * The unique ID of the Systemconfigurationtype
     * @type {number}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    fkiSystemconfigurationtypeID:number 
    /**
     * The unique ID of the Signature
     * @type {number}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    fkiSignatureID?:number 
    /**
     * The unique ID of the Ezsignuser
     * @type {number}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    fkiEzsignuserID?:number 
    /**
     * Whether if Ezsign is paid by the company or not
     * @type {boolean}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    bSystemconfigurationEzsignpaidbyoffice?:boolean 
    /**
     * 
     * @type {FieldESystemconfigurationEzsignofficeplan}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    eSystemconfigurationEzsignofficeplan?:FieldESystemconfigurationEzsignofficeplan 
    /**
     * 
     * @type {FieldEUserEzsignaccess}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    eUserEzsignaccess:FieldEUserEzsignaccess 
    /**
     * 
     * @type {FieldEUserEzsignprepaid}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    eUserEzsignprepaid?:FieldEUserEzsignprepaid 
    /**
     * Whether the User\'s eZsign subscription is a trial
     * @type {boolean}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    bUserEzsigntrial?:boolean 
    /**
     * The eZsign prepaid expiration date
     * @type {string}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    dtUserEzsignprepaidexpiration?:string 
    /**
     * An array of permissions granted to the user or api key
     * @type {Array<number>}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    a_pkiPermissionID:Array<number> 
    /**
     * 
     * @type {ActivesessionResponseCompoundUser}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    objUserReal:ActivesessionResponseCompoundUser 
    /**
     * 
     * @type {ActivesessionResponseCompoundUser}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    objUserCloned?:ActivesessionResponseCompoundUser 
    /**
     * 
     * @type {ActivesessionResponseCompoundApikey}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    objApikey?:ActivesessionResponseCompoundApikey 
    /**
     * An Array of Registered modules.  These are the modules that are Licensed to be used by the User or the API Key.
     * @type {Array<string>}
     * @memberof ActivesessionGetCurrentV1ResponseMPayload
     */
    a_eModuleInternalname:Array<string> 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectActivesessionResponseCompoundUser } from './'
// @ts-ignore
import { DataObjectActivesessionResponseCompoundUser } from './'
// @ts-ignore
import { DataObjectActivesessionResponseCompoundApikey } from './'
// @ts-ignore
import { ValidationObjectActivesessionResponseCompoundUser } from './'
// @ts-ignore
import { ValidationObjectActivesessionResponseCompoundUser } from './'
// @ts-ignore
import { ValidationObjectActivesessionResponseCompoundApikey } from './'

/**
 * @export 
 * A ActivesessionGetCurrentV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectActivesessionGetCurrentV1ResponseMPayload
 */
export class DataObjectActivesessionGetCurrentV1ResponseMPayload {
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
    fkiEzsignuserID?:number = undefined
    bSystemconfigurationEzsignpaidbyoffice?:boolean = undefined
    eSystemconfigurationEzsignofficeplan?:FieldESystemconfigurationEzsignofficeplan = undefined
    eUserEzsignaccess:FieldEUserEzsignaccess = 'No'
    eUserEzsignprepaid?:FieldEUserEzsignprepaid = undefined
    bUserEzsigntrial?:boolean = undefined
    dtUserEzsignprepaidexpiration?:string = undefined
    a_pkiPermissionID:Array<number> = []
    objUserReal:ActivesessionResponseCompoundUser = new DataObjectActivesessionResponseCompoundUser()
    objUserCloned?:ActivesessionResponseCompoundUser = undefined
    objApikey?:ActivesessionResponseCompoundApikey = undefined
    a_eModuleInternalname:Array<string> = []
}

/**
 * @export 
 * A ActivesessionGetCurrentV1ResponseMPayload Validation Object
 * @class ValidationObjectActivesessionGetCurrentV1ResponseMPayload
 */
export class ValidationObjectActivesessionGetCurrentV1ResponseMPayload {
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
   fkiEzsignuserID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   bSystemconfigurationEzsignpaidbyoffice = {
      type: 'boolean',
      required: false
   }
   eSystemconfigurationEzsignofficeplan = {
      type: 'enum',
      allowableValues: ['Standard','Pro'],
      required: false
   }
   eUserEzsignaccess = {
      type: 'enum',
      allowableValues: ['No','PaidByOffice','PerDocument','Prepaid'],
      required: true
   }
   eUserEzsignprepaid = {
      type: 'enum',
      allowableValues: ['No','Basic','Standard','Pro'],
      required: false
   }
   bUserEzsigntrial = {
      type: 'boolean',
      required: false
   }
   dtUserEzsignprepaidexpiration = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/,
      required: false
   }
   a_pkiPermissionID = {
      type: 'array',
      required: true
   }
   objUserReal = new ValidationObjectActivesessionResponseCompoundUser()
   objUserCloned = new ValidationObjectActivesessionResponseCompoundUser()
   objApikey = new ValidationObjectActivesessionResponseCompoundApikey()
   a_eModuleInternalname = {
      type: 'array',
      required: true
   }
} 


