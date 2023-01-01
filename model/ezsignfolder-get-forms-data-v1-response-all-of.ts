/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderGetFormsDataV1ResponseMPayload } from './ezsignfolder-get-forms-data-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignfolderGetFormsDataV1ResponseAllOf
 */
export interface EzsignfolderGetFormsDataV1ResponseAllOf {
    /**
     * 
     * @type {EzsignfolderGetFormsDataV1ResponseMPayload}
     * @memberof EzsignfolderGetFormsDataV1ResponseAllOf
     */
    'mPayload': EzsignfolderGetFormsDataV1ResponseMPayload;
}
/**
 * A EzsignfolderGetFormsDataV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderGetFormsDataV1ResponseAllOf
 */
export class DefaultObjectEzsignfolderGetFormsDataV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignfolderGetFormsDataV1ResponseMPayload> = {}
}


