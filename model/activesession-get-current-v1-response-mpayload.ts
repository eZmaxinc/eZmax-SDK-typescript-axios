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
import { ActivesessionResponseCompound } from './activesession-response-compound';
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

/**
 * @type ActivesessionGetCurrentV1ResponseMPayload
 * Payload for GET /1/object/activesession/getCurrent
 * @export
 */
export type ActivesessionGetCurrentV1ResponseMPayload = ActivesessionResponseCompound;



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
    pksCustomerCode:string = ''
    fkiSystemconfigurationtypeID?:number = undefined
    fkiSignatureID?:number = undefined
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
   pksCustomerCode = {
      type: 'string',
      required: true
   }
   fkiSystemconfigurationtypeID = {
      type: 'integer',
      minimum: 1,
      required: false
   }
   fkiSignatureID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
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


