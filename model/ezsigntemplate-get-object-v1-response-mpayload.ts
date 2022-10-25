/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatedocumentResponse } from './ezsigntemplatedocument-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignerResponseCompound } from './ezsigntemplatesigner-response-compound';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplateGetObjectV1ResponseMPayload
 * Payload for GET /1/object/ezsigntemplate/{pkiEzsigntemplateID}
 * @export
 */
export type EzsigntemplateGetObjectV1ResponseMPayload = EzsigntemplateResponseCompound;


/**
 * @export 
 * A EzsigntemplateGetObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplateGetObjectV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplateGetObjectV1ResponseMPayload extends DefaultObject {
   pkiEzsigntemplateID:number = 0
   fkiEzsigntemplatedocumentID?:number = undefined
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sLanguageNameX:string = ''
   sEzsigntemplateDescription:string = ''
   bEzsigntemplateAdminonly:boolean = false
   sEzsignfoldertypeNameX:string = ''
   objEzsigntemplatedocument?:Partial<EzsigntemplatedocumentResponse> = undefined
   a_objEzsigntemplatesigner:Array<EzsigntemplatesignerResponseCompound> = []
}


