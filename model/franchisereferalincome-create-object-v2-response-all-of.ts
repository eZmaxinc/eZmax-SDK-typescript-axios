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
import { FranchisereferalincomeCreateObjectV2ResponseMPayload } from './franchisereferalincome-create-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface FranchisereferalincomeCreateObjectV2ResponseAllOf
 */
export interface FranchisereferalincomeCreateObjectV2ResponseAllOf {
    /**
     * 
     * @type {FranchisereferalincomeCreateObjectV2ResponseMPayload}
     * @memberof FranchisereferalincomeCreateObjectV2ResponseAllOf
     */
    'mPayload': FranchisereferalincomeCreateObjectV2ResponseMPayload;
}
/**
 * A FranchisereferalincomeCreateObjectV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectFranchisereferalincomeCreateObjectV2ResponseAllOf
 */
export class DefaultObjectFranchisereferalincomeCreateObjectV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<FranchisereferalincomeCreateObjectV2ResponseMPayload> = {}
}


