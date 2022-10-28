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
import { UserAutocompleteElementResponse } from './user-autocomplete-element-response';

import { DefaultObject } from '../base'

/**
 * Payload for POST /2/object/user/getAutocomplete
 * @export
 * @interface UserGetAutocompleteV2ResponseMPayload
 */
export interface UserGetAutocompleteV2ResponseMPayload {
    /**
     * An array of User autocomplete element response.
     * @type {Array<UserAutocompleteElementResponse>}
     * @memberof UserGetAutocompleteV2ResponseMPayload
     */
    'a_objUser': Array<UserAutocompleteElementResponse>;
}
/**
 * A UserGetAutocompleteV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectUserGetAutocompleteV2ResponseMPayload
 */
export class DefaultObjectUserGetAutocompleteV2ResponseMPayload extends DefaultObject {
   a_objUser:Array<UserAutocompleteElementResponse> = []
}


