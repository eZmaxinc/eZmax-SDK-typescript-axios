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
import { EzsigntemplatepackagesignerResponseCompound } from './ezsigntemplatepackagesigner-response-compound';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatepackagesignerGetObjectV1ResponseMPayload
 * Payload for GET /1/object/ezsigntemplatepackagesigner/{pkiEzsigntemplatepackagesignerID}
 * @export
 */
export type EzsigntemplatepackagesignerGetObjectV1ResponseMPayload = EzsigntemplatepackagesignerResponseCompound;


/**
 * @export 
 * A EzsigntemplatepackagesignerGetObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatepackagesignerGetObjectV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplatepackagesignerGetObjectV1ResponseMPayload extends DefaultObject {
   pkiEzsigntemplatepackagesignerID:number = 0
   fkiEzsigntemplatepackageID:number = 0
   sEzsigntemplatepackagesignerDescription:string = ''
}


