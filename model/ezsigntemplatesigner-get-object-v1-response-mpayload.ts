/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignerResponseCompound } from './ezsigntemplatesigner-response-compound';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatesignerGetObjectV1ResponseMPayload
 * Payload for GET /1/object/ezsigntemplatesigner/{pkiEzsigntemplatesignerID}
 * @export
 */
export type EzsigntemplatesignerGetObjectV1ResponseMPayload = EzsigntemplatesignerResponseCompound;


/**
 * @export 
 * A EzsigntemplatesignerGetObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatesignerGetObjectV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplatesignerGetObjectV1ResponseMPayload extends DefaultObject {
   pkiEzsigntemplatesignerID:number = 0
   fkiEzsigntemplateID:number = 0
   sEzsigntemplatesignerDescription:string = ''
}


