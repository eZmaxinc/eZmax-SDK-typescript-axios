/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EzsignbulksendsignermappingResponseCompound } from './ezsignbulksendsignermapping-response-compound';

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
    /*'objEzsignbulksendsignermapping': EzsignbulksendsignermappingResponseCompound;*/
    'objEzsignbulksendsignermapping': EzsignbulksendsignermappingResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksendsignermappingResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendsignermappingResponseCompound } from './'

/**
 * @export 
 * A EzsignbulksendsignermappingGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendsignermappingGetObjectV2ResponseMPayload
 */
export class DataObjectEzsignbulksendsignermappingGetObjectV2ResponseMPayload {
   objEzsignbulksendsignermapping:EzsignbulksendsignermappingResponseCompound = new DataObjectEzsignbulksendsignermappingResponseCompound()
}

/**
 * @export 
 * A EzsignbulksendsignermappingGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsignbulksendsignermappingGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsignbulksendsignermappingGetObjectV2ResponseMPayload {
   objEzsignbulksendsignermapping = new ValidationObjectEzsignbulksendsignermappingResponseCompound()
} 


