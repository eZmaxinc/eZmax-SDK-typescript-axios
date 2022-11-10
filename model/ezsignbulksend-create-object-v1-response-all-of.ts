/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendCreateObjectV1ResponseMPayload } from './ezsignbulksend-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignbulksendCreateObjectV1ResponseAllOf
 */
export interface EzsignbulksendCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsignbulksendCreateObjectV1ResponseMPayload}
     * @memberof EzsignbulksendCreateObjectV1ResponseAllOf
     */
    'mPayload': EzsignbulksendCreateObjectV1ResponseMPayload;
}
/**
 * A EzsignbulksendCreateObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksendCreateObjectV1ResponseAllOf
 */
export class DefaultObjectEzsignbulksendCreateObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignbulksendCreateObjectV1ResponseMPayload> = {}
}


