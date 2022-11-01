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
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendResponse } from './ezsignbulksend-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendResponseCompoundAllOf } from './ezsignbulksend-response-compound-all-of';
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
 * @type EzsignbulksendResponseCompound
 * An Ezsignbulksend Object and children to create a complete structure
 * @export
 */
export type EzsignbulksendResponseCompound = EzsignbulksendResponse & EzsignbulksendResponseCompoundAllOf;


/**
 * @export 
 * A EzsignbulksendResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignbulksendResponseCompound
 */
export class DefaultObjectEzsignbulksendResponseCompound extends DefaultObject {
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


