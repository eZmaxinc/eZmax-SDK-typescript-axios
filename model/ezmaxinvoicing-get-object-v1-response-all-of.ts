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
import { EzmaxinvoicingGetObjectV1ResponseMPayload } from './ezmaxinvoicing-get-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzmaxinvoicingGetObjectV1ResponseAllOf
 */
export interface EzmaxinvoicingGetObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzmaxinvoicingGetObjectV1ResponseMPayload}
     * @memberof EzmaxinvoicingGetObjectV1ResponseAllOf
     */
    'mPayload': EzmaxinvoicingGetObjectV1ResponseMPayload;
}
/**
 * A EzmaxinvoicingGetObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzmaxinvoicingGetObjectV1ResponseAllOf
 */
export class DefaultObjectEzmaxinvoicingGetObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzmaxinvoicingGetObjectV1ResponseMPayload> = {}
}


