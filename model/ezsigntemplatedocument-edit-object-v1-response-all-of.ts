/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseWarning } from './common-response-warning';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatedocumentEditObjectV1ResponseAllOf
 */
export interface EzsigntemplatedocumentEditObjectV1ResponseAllOf {
    /**
     * 
     * @type {Array<CommonResponseWarning>}
     * @memberof EzsigntemplatedocumentEditObjectV1ResponseAllOf
     */
    'a_objWarning'?: Array<CommonResponseWarning>;
}
/**
 * A EzsigntemplatedocumentEditObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatedocumentEditObjectV1ResponseAllOf
 */
export class DefaultObjectEzsigntemplatedocumentEditObjectV1ResponseAllOf extends DefaultObject {
   a_objWarning?:Array<CommonResponseWarning> = undefined
}


