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
import { EzsigntemplateGetObjectV1ResponseMPayload } from './ezsigntemplate-get-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplateGetObjectV1ResponseAllOf
 */
export interface EzsigntemplateGetObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplateGetObjectV1ResponseMPayload}
     * @memberof EzsigntemplateGetObjectV1ResponseAllOf
     */
    'mPayload': EzsigntemplateGetObjectV1ResponseMPayload;
}
/**
 * A EzsigntemplateGetObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplateGetObjectV1ResponseAllOf
 */
export class DefaultObjectEzsigntemplateGetObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplateGetObjectV1ResponseMPayload> = {}
}


