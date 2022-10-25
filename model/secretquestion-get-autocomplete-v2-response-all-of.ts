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
import { SecretquestionGetAutocompleteV2ResponseMPayload } from './secretquestion-get-autocomplete-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface SecretquestionGetAutocompleteV2ResponseAllOf
 */
export interface SecretquestionGetAutocompleteV2ResponseAllOf {
    /**
     * 
     * @type {SecretquestionGetAutocompleteV2ResponseMPayload}
     * @memberof SecretquestionGetAutocompleteV2ResponseAllOf
     */
    'mPayload': SecretquestionGetAutocompleteV2ResponseMPayload;
}
/**
 * A SecretquestionGetAutocompleteV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectSecretquestionGetAutocompleteV2ResponseAllOf
 */
export class DefaultObjectSecretquestionGetAutocompleteV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<SecretquestionGetAutocompleteV2ResponseMPayload> = {}
}


