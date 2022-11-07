/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatedocumentResponseCompound } from './ezsigntemplatedocument-response-compound';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatedocumentGetObjectV1ResponseMPayload
 * Payload for GET /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}
 * @export
 */
export type EzsigntemplatedocumentGetObjectV1ResponseMPayload = EzsigntemplatedocumentResponseCompound;


/**
 * @export 
 * A EzsigntemplatedocumentGetObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatedocumentGetObjectV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplatedocumentGetObjectV1ResponseMPayload extends DefaultObject {
   pkiEzsigntemplatedocumentID:number = 0
   fkiEzsigntemplateID:number = 0
   sEzsigntemplatedocumentName:string = ''
   iEzsigntemplatedocumentPagetotal:number = 0
   iEzsigntemplatedocumentSignaturetotal:number = 0
}


