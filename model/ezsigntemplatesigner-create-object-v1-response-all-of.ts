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
import { EzsigntemplatesignerCreateObjectV1ResponseMPayload } from './ezsigntemplatesigner-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatesignerCreateObjectV1ResponseAllOf
 */
export interface EzsigntemplatesignerCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatesignerCreateObjectV1ResponseMPayload}
     * @memberof EzsigntemplatesignerCreateObjectV1ResponseAllOf
     */
    'mPayload': EzsigntemplatesignerCreateObjectV1ResponseMPayload;
}
/**
 * A EzsigntemplatesignerCreateObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignerCreateObjectV1ResponseAllOf
 */
export class DefaultObjectEzsigntemplatesignerCreateObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplatesignerCreateObjectV1ResponseMPayload> = {}
}


