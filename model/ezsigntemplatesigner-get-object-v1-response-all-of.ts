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
import { EzsigntemplatesignerGetObjectV1ResponseMPayload } from './ezsigntemplatesigner-get-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatesignerGetObjectV1ResponseAllOf
 */
export interface EzsigntemplatesignerGetObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatesignerGetObjectV1ResponseMPayload}
     * @memberof EzsigntemplatesignerGetObjectV1ResponseAllOf
     */
    'mPayload': EzsigntemplatesignerGetObjectV1ResponseMPayload;
}
/**
 * A EzsigntemplatesignerGetObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignerGetObjectV1ResponseAllOf
 */
export class DefaultObjectEzsigntemplatesignerGetObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplatesignerGetObjectV1ResponseMPayload> = {}
}


