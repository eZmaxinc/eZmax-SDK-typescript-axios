/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { ActivesessionResponse } from './activesession-response';
// May contain unused imports in some cases
// @ts-ignore
import { ActivesessionResponseCompoundApikey } from './activesession-response-compound-apikey';
// May contain unused imports in some cases
// @ts-ignore
import { ActivesessionResponseCompoundUser } from './activesession-response-compound-user';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEActivesessionOrigin } from './field-eactivesession-origin';
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
 * @type ActivesessionResponseCompound
 * Payload for GET /1/object/activesession/getCurrent
 * @export
 */
/*export type ActivesessionResponseCompound = ActivesessionResponse;*/
export interface ActivesessionResponseCompound {
    /**
     * 
     * @type {FieldEActivesessionUsertype}
     * @memberof ActivesessionResponseCompound
     */
    eActivesessionUsertype:FieldEActivesessionUsertype 
    /**
     * 
     * @type {FieldEActivesessionOrigin}
     * @memberof ActivesessionResponseCompound
     */
    eActivesessionOrigin:FieldEActivesessionOrigin 
    /**
     * 
     * @type {FieldEActivesessionWeekdaystart}
     * @memberof ActivesessionResponseCompound
     */
    eActivesessionWeekdaystart:FieldEActivesessionWeekdaystart 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof ActivesessionResponseCompound
     */
    fkiLanguageID:number 
    /**
     * The Name of the Company in the language of the requester
     * @type {string}
     * @memberof ActivesessionResponseCompound
     */
    sCompanyNameX:string 
    /**
     * The Name of the Department in the language of the requester
     * @type {string}
     * @memberof ActivesessionResponseCompound
     */
    sDepartmentNameX:string 
    /**
     * Whether the active session is in debug or not
     * @type {boolean}
     * @memberof ActivesessionResponseCompound
     */
    bActivesessionDebug:boolean 
    /**
     * Whether the active session is superadmin or not
     * @type {boolean}
     * @memberof ActivesessionResponseCompound
     */
    bActivesessionIssuperadmin:boolean 
    /**
     * The customer code assigned to your account
     * @type {string}
     * @memberof ActivesessionResponseCompound
     */
    pksCustomerCode:string 
    /**
     * The unique ID of the Systemconfigurationtype
     * @type {number}
     * @memberof ActivesessionResponseCompound
     */
    fkiSystemconfigurationtypeID:number 
    /**
     * The unique ID of the Signature
     * @type {number}
     * @memberof ActivesessionResponseCompound
     */
    fkiSignatureID?:number 
    /**
     * Whether if Ezsign is paid by the company or not
     * @type {boolean}
     * @memberof ActivesessionResponseCompound
     */
    bSystemconfigurationEzsignpaidbyoffice?:boolean 
    /**
     * 
     * @type {FieldESystemconfigurationEzsignofficeplan}
     * @memberof ActivesessionResponseCompound
     */
    eSystemconfigurationEzsignofficeplan?:FieldESystemconfigurationEzsignofficeplan 
    /**
     * 
     * @type {FieldEUserEzsignaccess}
     * @memberof ActivesessionResponseCompound
     */
    eUserEzsignaccess:FieldEUserEzsignaccess 
    /**
     * 
     * @type {FieldEUserEzsignprepaid}
     * @memberof ActivesessionResponseCompound
     */
    eUserEzsignprepaid?:FieldEUserEzsignprepaid 
    /**
     * The eZsign prepaid expiration date
     * @type {string}
     * @memberof ActivesessionResponseCompound
     */
    dtUserEzsignprepaidexpiration?:string 
    /**
     * An array of permissions granted to the user or api key
     * @type {Array<number>}
     * @memberof ActivesessionResponseCompound
     */
    a_pkiPermissionID:Array<number> 
    /**
     * 
     * @type {ActivesessionResponseCompoundUser}
     * @memberof ActivesessionResponseCompound
     */
    objUserReal:ActivesessionResponseCompoundUser 
    /**
     * 
     * @type {ActivesessionResponseCompoundUser}
     * @memberof ActivesessionResponseCompound
     */
    objUserCloned?:ActivesessionResponseCompoundUser 
    /**
     * 
     * @type {ActivesessionResponseCompoundApikey}
     * @memberof ActivesessionResponseCompound
     */
    objApikey?:ActivesessionResponseCompoundApikey 
    /**
     * An Array of Registered modules.  These are the modules that are Licensed to be used by the User or the API Key.
     * @type {Array<string>}
     * @memberof ActivesessionResponseCompound
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
 * A ActivesessionResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectActivesessionResponseCompound
 */
export class DataObjectActivesessionResponseCompound {
    eActivesessionUsertype:FieldEActivesessionUsertype = 'AgentBroker'
    eActivesessionOrigin:FieldEActivesessionOrigin = 'BuiltIn'
    eActivesessionWeekdaystart:FieldEActivesessionWeekdaystart = 'Sunday'
    fkiLanguageID:number = 0
    sCompanyNameX:string = ''
    sDepartmentNameX:string = ''
    bActivesessionDebug:boolean = false
    bActivesessionIssuperadmin:boolean = false
    pksCustomerCode:string = ''
    fkiSystemconfigurationtypeID:number = 0
    fkiSignatureID?:number = undefined
    bSystemconfigurationEzsignpaidbyoffice?:boolean = undefined
    eSystemconfigurationEzsignofficeplan?:FieldESystemconfigurationEzsignofficeplan = undefined
    eUserEzsignaccess:FieldEUserEzsignaccess = 'No'
    eUserEzsignprepaid?:FieldEUserEzsignprepaid = undefined
    dtUserEzsignprepaidexpiration?:string = undefined
    a_pkiPermissionID:Array<number> = []
    objUserReal:ActivesessionResponseCompoundUser = new DataObjectActivesessionResponseCompoundUser()
    objUserCloned?:ActivesessionResponseCompoundUser = undefined
    objApikey?:ActivesessionResponseCompoundApikey = undefined
    a_eModuleInternalname:Array<string> = []
}

/**
 * @export 
 * A ActivesessionResponseCompound Validation Object
 * @class ValidationObjectActivesessionResponseCompound
 */
export class ValidationObjectActivesessionResponseCompound {
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
   pksCustomerCode = {
      type: 'string',
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
   dtUserEzsignprepaidexpiration = {
      type: 'string',
      pattern: '/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/',
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


