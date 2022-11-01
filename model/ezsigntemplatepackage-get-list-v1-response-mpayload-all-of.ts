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
import { EzsigntemplatepackageListElement } from './ezsigntemplatepackage-list-element';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatepackageGetListV1ResponseMPayloadAllOf
 */
export interface EzsigntemplatepackageGetListV1ResponseMPayloadAllOf {
    /**
     * 
     * @type {Array<EzsigntemplatepackageListElement>}
     * @memberof EzsigntemplatepackageGetListV1ResponseMPayloadAllOf
     */
    'a_objEzsigntemplatepackage': Array<EzsigntemplatepackageListElement>;
}
/**
 * A EzsigntemplatepackageGetListV1ResponseMPayloadAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackageGetListV1ResponseMPayloadAllOf
 */
export class DefaultObjectEzsigntemplatepackageGetListV1ResponseMPayloadAllOf extends DefaultObject {
   a_objEzsigntemplatepackage:Array<EzsigntemplatepackageListElement> = []
}


