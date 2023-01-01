/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackageResponseCompound } from './ezsigntemplatepackage-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagemembershipResponseCompound } from './ezsigntemplatepackagemembership-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignerResponseCompound } from './ezsigntemplatepackagesigner-response-compound';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatepackageGetObjectV1ResponseMPayload
 * Payload for GET /1/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID}
 * @export
 */
export type EzsigntemplatepackageGetObjectV1ResponseMPayload = EzsigntemplatepackageResponseCompound;


/**
 * @export 
 * A EzsigntemplatepackageGetObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatepackageGetObjectV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplatepackageGetObjectV1ResponseMPayload extends DefaultObject {
   pkiEzsigntemplatepackageID:number = 0
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sLanguageNameX:string = ''
   sEzsigntemplatepackageDescription:string = ''
   bEzsigntemplatepackageAdminonly:boolean = false
   bEzsigntemplatepackageNeedvalidation:boolean = false
   bEzsigntemplatepackageIsactive:boolean = false
   sEzsignfoldertypeNameX:string = ''
   a_objEzsigntemplatepackagesigner:Array<EzsigntemplatepackagesignerResponseCompound> = []
   a_objEzsigntemplatepackagemembership:Array<EzsigntemplatepackagemembershipResponseCompound> = []
}


