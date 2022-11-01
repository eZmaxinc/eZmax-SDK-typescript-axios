/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
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
import { FieldEActivesessionUsertype } from './field-eactivesession-usertype';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEActivesessionWeekdaystart } from './field-eactivesession-weekdaystart';

import { DefaultObject } from '../base'

/**
 * @type ActivesessionGetCurrentV1ResponseMPayload
 * Payload for GET /1/object/activesession/getCurrent
 * @export
 */
export type ActivesessionGetCurrentV1ResponseMPayload = ActivesessionResponseCompound;


/**
 * @export 
 * A ActivesessionGetCurrentV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectActivesessionGetCurrentV1ResponseMPayload
 */
export class DefaultObjectActivesessionGetCurrentV1ResponseMPayload extends DefaultObject {
   eActivesessionUsertype:FieldEActivesessionUsertype = 'AgentBroker'
   eActivesessionWeekdaystart:FieldEActivesessionWeekdaystart = 'Sunday'
   fkiLanguageID:number = 0
   sCompanyNameX:string = ''
   sDepartmentNameX:string = ''
   bActivesessionDebug:boolean = false
   pksCustomerCode:string = ''
   fkiSystemconfigurationtypeID?:number = undefined
   a_pkiPermissionID:Array<number> = []
   objUserReal:Partial<ActivesessionResponseCompoundUser> = {}
   objUserCloned?:Partial<ActivesessionResponseCompoundUser> = undefined
   objApikey?:Partial<ActivesessionResponseCompoundApikey> = undefined
   a_eModuleInternalname:Array<string> = []
}


