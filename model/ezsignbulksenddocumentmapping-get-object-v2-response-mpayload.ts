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
import type { EzsignbulksenddocumentmappingResponseCompound } from './ezsignbulksenddocumentmapping-response-compound';

/**
 * Payload for GET /2/object/ezsignbulksenddocumentmapping/{pkiEzsignbulksenddocumentmappingID}
 * @export
 * @interface EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload
 */
export interface EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsignbulksenddocumentmappingResponseCompound}
     * @memberof EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload
     */
    /*'objEzsignbulksenddocumentmapping': EzsignbulksenddocumentmappingResponseCompound;*/
    'objEzsignbulksenddocumentmapping': EzsignbulksenddocumentmappingResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksenddocumentmappingResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksenddocumentmappingResponseCompound } from './'

/**
 * @export 
 * A EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksenddocumentmappingGetObjectV2ResponseMPayload
 */
export class DataObjectEzsignbulksenddocumentmappingGetObjectV2ResponseMPayload {
   objEzsignbulksenddocumentmapping:EzsignbulksenddocumentmappingResponseCompound = new DataObjectEzsignbulksenddocumentmappingResponseCompound()
}

/**
 * @export 
 * A EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsignbulksenddocumentmappingGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsignbulksenddocumentmappingGetObjectV2ResponseMPayload {
   objEzsignbulksenddocumentmapping = new ValidationObjectEzsignbulksenddocumentmappingResponseCompound()
} 


