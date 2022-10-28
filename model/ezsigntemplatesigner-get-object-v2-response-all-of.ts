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
import { EzsigntemplatesignerGetObjectV2ResponseMPayload } from './ezsigntemplatesigner-get-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatesignerGetObjectV2ResponseAllOf
 */
export interface EzsigntemplatesignerGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatesignerGetObjectV2ResponseMPayload}
     * @memberof EzsigntemplatesignerGetObjectV2ResponseAllOf
     */
    'mPayload': EzsigntemplatesignerGetObjectV2ResponseMPayload;
}
/**
 * A EzsigntemplatesignerGetObjectV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignerGetObjectV2ResponseAllOf
 */
export class DefaultObjectEzsigntemplatesignerGetObjectV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplatesignerGetObjectV2ResponseMPayload> = {}
}


