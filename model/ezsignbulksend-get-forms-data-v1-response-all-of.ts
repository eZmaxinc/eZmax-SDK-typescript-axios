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
import { EzsignbulksendGetFormsDataV1ResponseMPayload } from './ezsignbulksend-get-forms-data-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignbulksendGetFormsDataV1ResponseAllOf
 */
export interface EzsignbulksendGetFormsDataV1ResponseAllOf {
    /**
     * 
     * @type {EzsignbulksendGetFormsDataV1ResponseMPayload}
     * @memberof EzsignbulksendGetFormsDataV1ResponseAllOf
     */
    'mPayload': EzsignbulksendGetFormsDataV1ResponseMPayload;
}
/**
 * A EzsignbulksendGetFormsDataV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignbulksendGetFormsDataV1ResponseAllOf
 */
export class DefaultObjectEzsignbulksendGetFormsDataV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignbulksendGetFormsDataV1ResponseMPayload> = {}
}


