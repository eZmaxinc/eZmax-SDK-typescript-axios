/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendsignermappingResponseCompound } from './ezsignbulksendsignermapping-response-compound';

import { DefaultObject } from '../base'

/**
 * Payload for GET /2/object/ezsignbulksendsignermapping/{pkiEzsignbulksendsignermappingID}
 * @export
 * @interface EzsignbulksendsignermappingGetObjectV2ResponseMPayload
 */
export interface EzsignbulksendsignermappingGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsignbulksendsignermappingResponseCompound}
     * @memberof EzsignbulksendsignermappingGetObjectV2ResponseMPayload
     */
    'objEzsignbulksendsignermapping': EzsignbulksendsignermappingResponseCompound;
}
/**
 * A EzsignbulksendsignermappingGetObjectV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksendsignermappingGetObjectV2ResponseMPayload
 */
export class DefaultObjectEzsignbulksendsignermappingGetObjectV2ResponseMPayload extends DefaultObject {
   objEzsignbulksendsignermapping:Partial<EzsignbulksendsignermappingResponseCompound> = {}
}


