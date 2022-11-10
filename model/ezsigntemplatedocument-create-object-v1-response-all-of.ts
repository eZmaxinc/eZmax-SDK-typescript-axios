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
import { EzsigntemplatedocumentCreateObjectV1ResponseMPayload } from './ezsigntemplatedocument-create-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigntemplatedocumentCreateObjectV1ResponseAllOf
 */
export interface EzsigntemplatedocumentCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsigntemplatedocumentCreateObjectV1ResponseMPayload}
     * @memberof EzsigntemplatedocumentCreateObjectV1ResponseAllOf
     */
    'mPayload': EzsigntemplatedocumentCreateObjectV1ResponseMPayload;
}
/**
 * A EzsigntemplatedocumentCreateObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatedocumentCreateObjectV1ResponseAllOf
 */
export class DefaultObjectEzsigntemplatedocumentCreateObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigntemplatedocumentCreateObjectV1ResponseMPayload> = {}
}


