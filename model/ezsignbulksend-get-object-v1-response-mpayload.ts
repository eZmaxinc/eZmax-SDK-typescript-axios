/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendResponseCompound } from './ezsignbulksend-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksenddocumentmappingResponseCompound } from './ezsignbulksenddocumentmapping-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendsignermappingResponse } from './ezsignbulksendsignermapping-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfoldertypePrivacylevel } from './field-eezsignfoldertype-privacylevel';

import { DefaultObject } from '../base'

/**
 * @type EzsignbulksendGetObjectV1ResponseMPayload
 * Payload for GET /1/object/ezsignbulksend/{pkiEzsignbulksendID}
 * @export
 */
export type EzsignbulksendGetObjectV1ResponseMPayload = EzsignbulksendResponseCompound;


/**
 * @export 
 * A EzsignbulksendGetObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignbulksendGetObjectV1ResponseMPayload
 */
export class DefaultObjectEzsignbulksendGetObjectV1ResponseMPayload extends DefaultObject {
   pkiEzsignbulksendID:number = 0
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sLanguageNameX:string = ''
   eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel = 'User'
   sEzsignfoldertypeNameX:string = ''
   sEzsignbulksendDescription:string = ''
   tEzsignbulksendNote:string = ''
   bEzsignbulksendNeedvalidation:boolean = false
   bEzsignbulksendIsactive:boolean = false
   objAudit:Partial<CommonAudit> = {}
   a_objEzsignbulksenddocumentmapping:Array<EzsignbulksenddocumentmappingResponseCompound> = []
   a_objEzsignbulksendsignermapping:Array<EzsignbulksendsignermappingResponse> = []
}


