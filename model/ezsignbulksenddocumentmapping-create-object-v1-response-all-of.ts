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
import { EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload } from './ezsignbulksenddocumentmapping-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignbulksenddocumentmappingCreateObjectV1ResponseAllOf
 */
export interface EzsignbulksenddocumentmappingCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload}
     * @memberof EzsignbulksenddocumentmappingCreateObjectV1ResponseAllOf
     */
    'mPayload': EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload;
}
/**
 * A EzsignbulksenddocumentmappingCreateObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseAllOf
 */
export class DefaultObjectEzsignbulksenddocumentmappingCreateObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignbulksenddocumentmappingCreateObjectV1ResponseMPayload> = {}
}


