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
import { EzsigntemplatepackagesignermembershipResponseCompound } from './ezsigntemplatepackagesignermembership-response-compound';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatepackagesignermembershipGetObjectV1ResponseMPayload
 * Payload for GET /1/object/ezsigntemplatepackagesignermembership/{pkiEzsigntemplatepackagesignermembershipID}
 * @export
 */
export type EzsigntemplatepackagesignermembershipGetObjectV1ResponseMPayload = EzsigntemplatepackagesignermembershipResponseCompound;


/**
 * @export 
 * A EzsigntemplatepackagesignermembershipGetObjectV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatepackagesignermembershipGetObjectV1ResponseMPayload
 */
export class DefaultObjectEzsigntemplatepackagesignermembershipGetObjectV1ResponseMPayload extends DefaultObject {
   pkiEzsigntemplatepackagesignermembershipID:number = 0
   fkiEzsigntemplatepackagemembershipID:number = 0
   fkiEzsigntemplatepackagesignerID:number = 0
   fkiEzsigntemplatesignerID:number = 0
   iEzsigntemplatepackagesignermembershipCopy?:number = undefined
}


