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
import { EzsignbulksenddocumentmappingRequestCompound } from './ezsignbulksenddocumentmapping-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for POST /1/object/ezsignbulksenddocumentmapping
 * @export
 * @interface EzsignbulksenddocumentmappingCreateObjectV1Request
 */
export interface EzsignbulksenddocumentmappingCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsignbulksenddocumentmappingRequestCompound>}
     * @memberof EzsignbulksenddocumentmappingCreateObjectV1Request
     */
    'a_objEzsignbulksenddocumentmapping': Array<EzsignbulksenddocumentmappingRequestCompound>;
}
/**
 * A EzsignbulksenddocumentmappingCreateObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksenddocumentmappingCreateObjectV1Request
 */
export class DefaultObjectEzsignbulksenddocumentmappingCreateObjectV1Request extends DefaultObject {
   a_objEzsignbulksenddocumentmapping:Array<EzsignbulksenddocumentmappingRequestCompound> = []
}


