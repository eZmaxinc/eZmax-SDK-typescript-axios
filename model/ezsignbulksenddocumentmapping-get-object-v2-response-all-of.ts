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
import { EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload } from './ezsignbulksenddocumentmapping-get-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignbulksenddocumentmappingGetObjectV2ResponseAllOf
 */
export interface EzsignbulksenddocumentmappingGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload}
     * @memberof EzsignbulksenddocumentmappingGetObjectV2ResponseAllOf
     */
    'mPayload': EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload;
}
/**
 * A EzsignbulksenddocumentmappingGetObjectV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksenddocumentmappingGetObjectV2ResponseAllOf
 */
export class DefaultObjectEzsignbulksenddocumentmappingGetObjectV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignbulksenddocumentmappingGetObjectV2ResponseMPayload> = {}
}

