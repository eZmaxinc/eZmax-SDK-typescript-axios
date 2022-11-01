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
import { BrandingListElement } from './branding-list-element';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface BrandingGetListV1ResponseMPayloadAllOf
 */
export interface BrandingGetListV1ResponseMPayloadAllOf {
    /**
     * 
     * @type {Array<BrandingListElement>}
     * @memberof BrandingGetListV1ResponseMPayloadAllOf
     */
    'a_objBranding': Array<BrandingListElement>;
}
/**
 * A BrandingGetListV1ResponseMPayloadAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectBrandingGetListV1ResponseMPayloadAllOf
 */
export class DefaultObjectBrandingGetListV1ResponseMPayloadAllOf extends DefaultObject {
   a_objBranding:Array<BrandingListElement> = []
}


